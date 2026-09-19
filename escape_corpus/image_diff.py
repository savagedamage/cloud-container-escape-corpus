#!/usr/bin/env python3
"""
image_diff.py - OCI Image Layer Delta Analysis

Treats container images as binaries: computes a risk-weighted delta between two
image tags by flattening both images and diffing the merged filesystems.

Detects: new binaries (ELF, setuid, file capabilities), new entrypoints,
changed cmd/env (secret-value aware), sensitive path changes, layer anomalies.

Requirements: crane (github.com/google/go-containerregistry/cmd/crane) on PATH,
or skopeo as fallback; libcap2-bin (getcap) for file-capability checks.

Usage:
    image_diff.py <old_image> <new_image> [--output diff.json]
    image_diff.py nginx:1.23 nginx:1.24 --output diff.json
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class FileChange:
    path: str
    change_type: str  # added, modified, deleted
    size_old: int
    size_new: int
    sha256_old: Optional[str]
    sha256_new: Optional[str]
    risk_score: int
    risk_factors: List[str]


@dataclass
class ImageDiffResult:
    image_old: str
    image_new: str
    files_added: int
    files_removed: int
    files_modified: int
    changes: List[FileChange]
    new_binaries: List[str]
    new_capabilities: List[str]
    entrypoint_changed: bool
    cmd_changed: bool
    user_changed: bool
    env_changes: Dict[str, List[Optional[str]]]
    total_risk_score: int
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    # Package-level view of the same delta (dpkg/apk inventories). Empty when the
    # images carry a package database this tool does not parse.
    packages: Dict = field(default_factory=dict)
    package_format: Optional[str] = None


RISK_WEIGHTS = {
    "new_binary": 25,
    "new_setuid_binary": 40,
    "new_capability_binary": 35,
    "entrypoint_change": 30,
    "cmd_change": 15,
    "user_change": 10,
    "env_secret_added": 20,
    "env_changed": 5,
    "sensitive_path_added": 25,
    "sensitive_path_modified": 15,
    "script_added": 10,
    "cert_key_added": 30,
    "ssh_key_added": 35,
    "large_file": 20,
}

SENSITIVE_PATHS = [
    r"^/etc/(passwd|shadow|sudoers|group)$",
    r"^/root/\.ssh/",
    r"^/home/[^/]+/\.ssh/",
    r"^/etc/ssh/.*_key",
    r"/\.docker/config\.json$",
    r"/\.aws/credentials$",
    r"/\.kube/config$",
    r"^/var/run/secrets/",
    r"^/etc/kubernetes/",
    r"^/etc/cron",
    r"^/etc/systemd/",
    r"^/etc/selinux/",
    r"^/etc/apparmor",
    r"^/usr/lib/systemd/",
    r"^/lib/systemd/system/",
]

CAPABILITY_BINARIES = {
    "cap_setuid", "cap_setgid", "cap_sys_admin", "cap_sys_ptrace",
    "cap_dac_override", "cap_dac_read_search", "cap_sys_module",
    "cap_sys_rawio", "cap_net_raw", "cap_net_admin", "cap_bpf",
}

DANGEROUS_BINARIES = {
    "nc", "netcat", "ncat", "socat", "curl", "wget", "python3", "python",
    "perl", "ruby", "php", "node", "bash", "sh", "dash", "awk", "sed",
    "base64", "openssl", "gdb", "strace", "ltrace", "nsenter", "unshare",
    "mount", "umount", "iptables", "ip", "ss", "tcpdump", "nmap", "kubectl",
}

CRANE = shutil.which("crane") or ""
SKOPEO = shutil.which("skopeo") or ""
GETCAP = shutil.which("getcap") or ""


def run_cmd(cmd: List[str], timeout: int = 300) -> Tuple[int, str, str]:
    """Run command and return (exit_code, stdout, stderr)."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as e:
        return -1, "", str(e)


def get_image_config(image: str) -> dict:
    """Resolve multi-arch automatically and return the image config JSON."""
    if CRANE:
        code, out, err = run_cmd([CRANE, "config", image])
        if code == 0 and out.strip():
            try:
                return json.loads(out)
            except json.JSONDecodeError:
                pass
    if SKOPEO:
        code, out, err = run_cmd([SKOPEO, "inspect", f"docker://{image}"])
        if code == 0 and out.strip():
            return json.loads(out)
    raise RuntimeError(f"Failed to get config for {image} (crane={CRANE or 'missing'}, skopeo={SKOPEO or 'missing'})")


def pull_image_tar(image: str, dest_tar: Path) -> None:
    """Pull image to a local tar archive via crane or skopeo."""
    if CRANE:
        code, out, err = run_cmd([CRANE, "pull", image, str(dest_tar)])
        if code == 0:
            return
    if SKOPEO:
        code, out, err = run_cmd([SKOPEO, "copy", f"docker://{image}", f"docker-archive:{dest_tar}"])
        if code == 0:
            return
    raise RuntimeError(f"Failed to pull {image}")


def safe_extract_layer(lt: tarfile.TarFile, dest: Path) -> Dict[str, str]:
    """Extract one layer tar member-by-member with containment checks, preserving
    symlinks (incl. absolute targets, never followed), hardlinks, mode bits
    (incl. setuid) and file-capability xattrs. Returns hardlink map rel->target."""
    hardlinks: Dict[str, str] = {}
    for m in lt.getmembers():
        name = m.name
        if name.startswith("/") or ".." in name or name.startswith(".."):
            continue  # absolute or escaping paths: skip, never write outside dest
        target = os.path.join(dest, name)
        parent = os.path.dirname(target)

        if m.isdir():
            os.makedirs(target, exist_ok=True)
        elif m.issym():
            os.makedirs(parent, exist_ok=True)
            if os.path.lexists(target):
                os.unlink(target)
            try:
                os.symlink(m.linkname, target)  # absolute targets dangle safely in sandbox
            except OSError:
                pass
        elif m.islnk():
            os.makedirs(parent, exist_ok=True)
            link_src = os.path.join(dest, m.linkname)
            if os.path.lexists(target):
                os.unlink(target)
            try:
                os.link(link_src, target)
                hardlinks["/" + name] = "/" + m.linkname
            except OSError:
                src = lt.extractfile(m)
                if src:
                    with open(target, "wb") as f:
                        shutil.copyfileobj(src, f)
                os.chmod(target, m.mode)
        elif m.isfile():
            os.makedirs(parent, exist_ok=True)
            src = lt.extractfile(m)
            if src:
                with open(target, "wb") as f:
                    shutil.copyfileobj(src, f)
            os.chmod(target, m.mode)  # preserve setuid/setgid/sticky
            cap_hex = m.pax_headers.get("SCHILY.xattr.security.capability")
            if cap_hex:
                try:
                    os.setxattr(target, "security.capability", bytes.fromhex(cap_hex))
                except OSError:
                    pass
        # fifos/device nodes/whiteouts: skipped intentionally
    return hardlinks


def flatten_image_tar(tar_path: Path, workdir: Path) -> Tuple[Dict[str, dict], List[str], Path]:
    """Extract all layers of a pulled image tar (in order, later wins) and return
    {relpath: {type, ...}}, ordered layer blob names, and merge dir."""
    layer_names: List[str] = []
    flat: Dict[str, dict] = {}
    hardlinks: Dict[str, str] = {}  # relpath -> linkname (hardlink targets)

    with tarfile.open(tar_path, "r") as tf:
        manifest_member = None
        for m in tf.getmembers():
            if m.name == "manifest.json":
                manifest_member = m
                break
        if manifest_member is None:
            raise RuntimeError(f"No manifest.json in {tar_path}")
        mf = tf.extractfile(manifest_member)
        if mf is None:
            raise RuntimeError(f"Cannot read manifest.json from {tar_path}")
        manifest = json.loads(mf.read())
        layer_names = list(manifest[0].get("Layers", []))

        merge_dir = workdir / "merge"
        merge_dir.mkdir(parents=True, exist_ok=True)

        for i, layer_name in enumerate(layer_names):
            layer_dir = workdir / f"layer_{i}"
            layer_dir.mkdir(parents=True, exist_ok=True)
            try:
                member = tf.getmember(layer_name)
            except KeyError:
                continue  # layer blob not present (e.g. foreign layer)
            fobj = tf.extractfile(member)
            with tarfile.open(fileobj=fobj, mode="r:gz") as lt:
                hardlinks.update(safe_extract_layer(lt, layer_dir))

        # Merge in order: later layers overwrite earlier ones
        for i in range(len(layer_names)):
            layer_dir = workdir / f"layer_{i}"
            if not layer_dir.exists():
                continue
            for root, _dirs, files in os.walk(layer_dir):
                for f in files:
                    src = Path(root) / f
                    rel = src.relative_to(layer_dir)
                    dst = merge_dir / rel
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    # Clear existing entry so later layers can replace any type
                    if os.path.lexists(dst):
                        if os.path.isdir(dst) and not os.path.islink(dst):
                            shutil.rmtree(dst)
                        else:
                            os.unlink(dst)
                    if os.path.islink(src):
                        os.symlink(os.readlink(src), dst)
                    else:
                        shutil.copy2(src, dst)
                        try:
                            cap = os.getxattr(src, "security.capability")
                            os.setxattr(dst, "security.capability", cap)
                        except OSError:
                            pass

    # Hash the merged filesystem (symlinks/hardlinks recorded by target, not content)
    for root, _dirs, files in os.walk(merge_dir):
        for f in files:
            p = Path(root) / f
            rel = "/" + str(p.relative_to(merge_dir))
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if rel in hardlinks:
                flat[rel] = {
                    "type": "hardlink",
                    "target": hardlinks[rel],
                }
            elif os.path.islink(p):
                flat[rel] = {
                    "type": "symlink",
                    "target": os.readlink(p),
                }
            else:
                flat[rel] = {
                    "type": "file",
                    "sha256": get_file_sha256(p),
                    "size": st.st_size,
                    "mode": st.st_mode,
                }

    return flat, layer_names, merge_dir


def get_file_sha256(path: Path) -> str:
    """Compute SHA256 of file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def check_file_capabilities(abs_path: Path) -> Set[str]:
    """Get file capabilities using getcap."""
    if not GETCAP:
        return set()
    code, out, err = run_cmd([GETCAP, str(abs_path)], timeout=30)
    if code == 0 and out.strip():
        caps = set()
        for line in out.strip().split("\n"):
            if "=" in line:
                cap_str = line.split("=", 1)[1].strip()
                caps.update(cap_str.split(","))
        return caps
    return set()


def is_elf_binary(abs_path: Path) -> bool:
    """Check if file is an ELF binary."""
    try:
        with open(abs_path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except Exception:
        return False


def assess_file_risk(rel: str, change_type: str, size: int, mode: int,
                     abs_path: Optional[Path]) -> Tuple[int, List[str]]:
    """Assess risk score for a file change."""
    score = 0
    factors = []
    is_new = change_type == "added"

    if is_new:
        is_elf = False
        if abs_path is not None and abs_path.exists():
            is_elf = is_elf_binary(abs_path)
        if is_elf or (mode & 0o111):
            score += RISK_WEIGHTS["new_binary"]
            factors.append("new_binary")
            if mode & 0o4000:
                score += RISK_WEIGHTS["new_setuid_binary"]
                factors.append("setuid")
            if abs_path is not None and abs_path.exists():
                caps = check_file_capabilities(abs_path)
                if caps & CAPABILITY_BINARIES:
                    score += RISK_WEIGHTS["new_capability_binary"]
                    factors.append(f"caps:{','.join(sorted(caps & CAPABILITY_BINARIES))}")

        basename = os.path.basename(rel)
        if basename in DANGEROUS_BINARIES:
            factors.append(f"dangerous_binary:{basename}")

        if rel.endswith((".sh", ".py", ".pl", ".rb", ".js", ".php")):
            score += RISK_WEIGHTS["script_added"]
            factors.append("script")

        if any(rel.endswith(ext) for ext in [".pem", ".key", ".crt", ".p12", ".pfx"]):
            score += RISK_WEIGHTS["cert_key_added"]
            factors.append("certificate_key")

        if "ssh" in rel and ("id_" in rel or "authorized_keys" in rel):
            score += RISK_WEIGHTS["ssh_key_added"]
            factors.append("ssh_key")

        if size > 50 * 1024 * 1024:
            score += RISK_WEIGHTS["large_file"]
            factors.append(f"large_file:{size // (1024 * 1024)}MB")

    for pattern in SENSITIVE_PATHS:
        if re.search(pattern, rel):
            if is_new:
                score += RISK_WEIGHTS["sensitive_path_added"]
                factors.append("sensitive_path")
            else:
                score += RISK_WEIGHTS["sensitive_path_modified"]
                factors.append("sensitive_path_modified")
            break

    return score, factors


def diff_filesystems(old_flat: Dict[str, dict], new_flat: Dict[str, dict],
                     new_merge_dir: Path) -> Tuple[List[FileChange], List[str], List[str]]:
    """Diff two flattened filesystems; return changes, new binaries, new capabilities."""
    changes: List[FileChange] = []
    new_binaries: List[str] = []
    new_capabilities: List[str] = []

    old_paths = set(old_flat.keys())
    new_paths = set(new_flat.keys())

    for path in sorted(new_paths - old_paths):
        info = new_flat[path]
        abs_path = new_merge_dir / path.lstrip("/")
        if info.get("type") in ("symlink", "hardlink"):
            risk, factors = assess_file_risk(path, "added", 0, 0, None)
            changes.append(FileChange(
                path=path, change_type="added", size_old=0, size_new=0,
                sha256_old=None, sha256_new=None,
                risk_score=risk, risk_factors=factors + [f"{info['type']}:{info['target']}"],
            ))
        else:
            risk, factors = assess_file_risk(path, "added", info["size"], info["mode"], abs_path)
            changes.append(FileChange(
                path=path, change_type="added", size_old=0, size_new=info["size"],
                sha256_old=None, sha256_new=info["sha256"],
                risk_score=risk, risk_factors=factors,
            ))
        if "new_binary" in factors:
            new_binaries.append(path)
        if any(f.startswith("caps:") for f in factors):
            new_capabilities.append(path)

    for path in sorted(old_paths - new_paths):
        info = old_flat[path]
        size_old = info.get("size", 0)
        sha_old = info.get("sha256")
        changes.append(FileChange(
            path=path, change_type="deleted", size_old=size_old, size_new=0,
            sha256_old=sha_old, sha256_new=None,
            risk_score=0, risk_factors=[],
        ))

    for path in sorted(old_paths & new_paths):
        o, n = old_flat[path], new_flat[path]
        changed = False
        if o.get("type") != n.get("type"):
            changed = True
        elif o.get("type") in ("symlink", "hardlink"):
            changed = o.get("target") != n.get("target")
        else:
            changed = o.get("sha256") != n.get("sha256")

        if changed:
            abs_path = new_merge_dir / path.lstrip("/")
            if n.get("type") in ("symlink", "hardlink"):
                risk, factors = assess_file_risk(path, "modified", 0, 0, None)
            else:
                risk, factors = assess_file_risk(path, "modified", n.get("size", 0), n.get("mode", 0), abs_path)
            changes.append(FileChange(
                path=path, change_type="modified",
                size_old=o.get("size", 0), size_new=n.get("size", 0),
                sha256_old=o.get("sha256"), sha256_new=n.get("sha256"),
                risk_score=risk, risk_factors=factors,
            ))

    return changes, new_binaries, new_capabilities


def parse_env(env_list: List[str]) -> Dict[str, str]:
    result = {}
    for item in env_list or []:
        if "=" in item:
            k, v = item.split("=", 1)
            result[k] = v
    return result


def diff_configs(config_old: dict, config_new: dict) -> Tuple[bool, bool, bool, Dict[str, List[Optional[str]]]]:
    """Compare image configs: entrypoint, cmd, user, env."""
    c_old = config_old.get("config", {}) or {}
    c_new = config_new.get("config", {}) or {}

    entrypoint_changed = c_old.get("Entrypoint") != c_new.get("Entrypoint")
    cmd_changed = c_old.get("Cmd") != c_new.get("Cmd")
    user_changed = c_old.get("User") != c_new.get("User")

    env_old = parse_env(c_old.get("Env", []))
    env_new = parse_env(c_new.get("Env", []))
    env_changes: Dict[str, List[Optional[str]]] = {}
    for k in sorted(set(env_old) | set(env_new)):
        if env_old.get(k) != env_new.get(k):
            env_changes[k] = [env_old.get(k), env_new.get(k)]

    return entrypoint_changed, cmd_changed, user_changed, env_changes


def compute_risk_level(score: int) -> str:
    if score >= 100:
        return "CRITICAL"
    elif score >= 50:
        return "HIGH"
    elif score >= 20:
        return "MEDIUM"
    return "LOW"


def main():
    parser = argparse.ArgumentParser(description="OCI Image Layer Delta Analysis")
    parser.add_argument("old_image", help="Old image reference (e.g., nginx:1.23)")
    parser.add_argument("new_image", help="New image reference (e.g., nginx:1.24)")
    parser.add_argument("-o", "--output", help="Output JSON file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print every risky file change")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        print(f"[*] Pulling {args.old_image} ...")
        old_tar = tmp / "old.tar"
        pull_image_tar(args.old_image, old_tar)

        print(f"[*] Pulling {args.new_image} ...")
        new_tar = tmp / "new.tar"
        pull_image_tar(args.new_image, new_tar)

        print("[*] Getting image configs ...")
        config_old = get_image_config(args.old_image)
        config_new = get_image_config(args.new_image)

        print("[*] Flattening old image ...")
        old_flat, old_layers, old_merge_dir = flatten_image_tar(old_tar, tmp / "old")
        print(f"    {len(old_flat)} files across {len(old_layers)} layers")

        print("[*] Flattening new image ...")
        new_flat, new_layers, new_merge_dir = flatten_image_tar(new_tar, tmp / "new")
        print(f"    {len(new_flat)} files across {len(new_layers)} layers")

        print("[*] Computing package delta ...")
        from .packages import diff_packages, inventory_from_merge, summarise
        old_pkgs, old_fmt = inventory_from_merge(old_merge_dir, old_flat)
        new_pkgs, new_fmt = inventory_from_merge(new_merge_dir, new_flat)
        pkg_delta = diff_packages(old_pkgs, new_pkgs) if (old_pkgs or new_pkgs) else {}
        pkg_fmt = new_fmt or old_fmt
        print(f"    {summarise(pkg_delta, pkg_fmt)}" if pkg_delta
              else "    Package inventory: unavailable (no dpkg/apk database in either image)")

        print("[*] Computing filesystem delta ...")
        changes, new_binaries, new_capabilities = diff_filesystems(old_flat, new_flat, new_merge_dir)
        files_added = sum(1 for c in changes if c.change_type == "added")
        files_removed = sum(1 for c in changes if c.change_type == "deleted")
        files_modified = sum(1 for c in changes if c.change_type == "modified")

        print("[*] Computing config diff ...")
        entrypoint_changed, cmd_changed, user_changed, env_changes = diff_configs(config_old, config_new)

        risk_score = sum(c.risk_score for c in changes)
        if entrypoint_changed:
            risk_score += RISK_WEIGHTS["entrypoint_change"]
        if cmd_changed:
            risk_score += RISK_WEIGHTS["cmd_change"]
        if user_changed:
            risk_score += RISK_WEIGHTS["user_change"]
        for k, (old_v, new_v) in env_changes.items():
            if re.search(r"(secret|key|token|password|passwd|credential)", k, re.I):
                if new_v and not old_v:
                    risk_score += RISK_WEIGHTS["env_secret_added"]
            else:
                risk_score += RISK_WEIGHTS["env_changed"]

        risky = [c for c in changes if c.risk_score > 0]

        result = ImageDiffResult(
            image_old=args.old_image,
            image_new=args.new_image,
            files_added=files_added,
            files_removed=files_removed,
            files_modified=files_modified,
            changes=risky,
            new_binaries=new_binaries,
            new_capabilities=new_capabilities,
            entrypoint_changed=entrypoint_changed,
            cmd_changed=cmd_changed,
            user_changed=user_changed,
            env_changes=env_changes,
            total_risk_score=risk_score,
            risk_level=compute_risk_level(risk_score),
            packages=pkg_delta,
            package_format=pkg_fmt,
        )

        output = asdict(result)
        if args.output:
            with open(args.output, "w") as f:
                json.dump(output, f, indent=2)
            print(f"\n[+] Results written to {args.output}")

        print("\n=== Image Diff Report ===")
        print(f"{args.old_image} -> {args.new_image}")
        print(f"Files: +{files_added} -{files_removed} ~{files_modified}")
        print(f"New binaries: {len(new_binaries)} | New file capabilities: {len(new_capabilities)}")
        print(f"Entrypoint changed: {entrypoint_changed} | Cmd changed: {cmd_changed} | User changed: {user_changed}")
        print(f"Env changes: {len(env_changes)}")
        print(f"Risk score: {risk_score} -> {result.risk_level}")

        if new_binaries:
            print("\n[New binaries]")
            for b in new_binaries[:20]:
                print(f"  + {b}")
        if new_capabilities:
            print("\n[New file capabilities]")
            for c in new_capabilities[:20]:
                print(f"  ! {c}")
        if env_changes:
            print("\n[Env changes]")
            for k, (o, n) in env_changes.items():
                print(f"  {k}: {o!r} -> {n!r}")

        if args.verbose:
            print("\n[All risky file changes]")
            for c in risky:
                print(f"  [{c.change_type}] {c.path} (risk={c.risk_score} {','.join(c.risk_factors)})")


if __name__ == "__main__":
    main()
