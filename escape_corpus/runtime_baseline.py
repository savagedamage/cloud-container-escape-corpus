#!/usr/bin/env python3
"""
runtime_baseline.py - Container Runtime Drift Baseline

Treats runtime state as device posture: takes a hash-chained snapshot of
/proc/cgroup/cap state and detects drift from the baseline.

Usage:
    runtime_baseline.py baseline --container <id> --output baseline.json
    runtime_baseline.py verify --container <id> --baseline baseline.json
    runtime_baseline.py monitor --container <id> --baseline baseline.json --interval 30
"""

import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple


@dataclass
class CapabilitySnapshot:
    cap_eff: str
    cap_prm: str
    cap_inh: str
    cap_bnd: str
    cap_amb: str
    securebits: str
    seccomp_mode: str
    no_new_privs: bool


@dataclass
class CgroupSnapshot:
    cgroup_path: str
    cgroup_version: str
    controllers: List[str]
    cpu_limit: Optional[str]
    memory_limit: Optional[str]
    pids_limit: Optional[str]
    cgroup_procs_count: int


@dataclass
class NamespaceSnapshot:
    pid_ns: str
    mnt_ns: str
    net_ns: str
    uts_ns: str
    ipc_ns: str
    user_ns: str
    cgroup_ns: str
    time_ns: str


@dataclass
class ProcSnapshot:
    pid: int
    ppid: int
    uid: int
    gid: int
    cmdline: str
    exe_link: str
    root_link: str
    mounted_procs: List[str]
    mounted_sys: bool
    host_pid_visible: bool


@dataclass
class MountSnapshot:
    docker_sock: bool
    containerd_sock: bool
    cri_o_sock: bool
    host_root: bool
    host_proc: bool
    host_sys: bool
    sensitive_mounts: List[str]
    read_only_rootfs: bool


@dataclass
class RuntimeSnapshot:
    timestamp: str
    container_id: str
    capabilities: CapabilitySnapshot
    cgroups: CgroupSnapshot
    namespaces: NamespaceSnapshot
    proc: ProcSnapshot
    mounts: MountSnapshot
    hash_chain: str
    previous_hash: Optional[str] = None


class RuntimeBaseline:
    """Collect and verify container runtime state."""

    DANGEROUS_CAPS = {
        "cap_sys_admin", "cap_sys_ptrace", "cap_sys_module", "cap_sys_rawio",
        "cap_sys_boot", "cap_sys_time", "cap_sys_resource", "cap_mknod",
        "cap_net_admin", "cap_net_raw", "cap_bpf", "cap_perfmon",
        "cap_dac_override", "cap_dac_read_search", "cap_setuid", "cap_setgid",
        "cap_setpcap", "cap_linux_immutable", "cap_audit_control",
        "cap_audit_write", "cap_sys_chroot", "cap_sys_pacct", "cap_wake_alarm",
        "cap_block_suspend", "cap_audit_read", "cap_lease",
        "cap_syslog", "cap_checkpoint_restore", "cap_mac_override",
        "cap_mac_admin", "cap_sys_nice", "cap_sys_tty_config",
    }

    def __init__(self, container_id: str, use_docker: bool = True,
                 use_podman: bool = False, use_crictl: bool = False):
        self.container_id = container_id
        self.use_docker = use_docker
        self.use_podman = use_podman
        self.use_crictl = use_crictl

    def _run_in_container(self, cmd: List[str]) -> Tuple[int, str]:
        """Execute command inside container."""
        if self.use_docker:
            full_cmd = ["docker", "exec", self.container_id] + cmd
        elif self.use_podman:
            full_cmd = ["podman", "exec", self.container_id] + cmd
        elif self.use_crictl:
            full_cmd = ["crictl", "exec", self.container_id] + cmd
        else:
            return -1, "no runtime selected"

        try:
            result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=30)
            return result.returncode, result.stdout
        except subprocess.TimeoutExpired:
            return -1, "timeout"
        except Exception as e:
            return -1, str(e)

    def _read_file_in_container(self, path: str) -> Optional[str]:
        """Read a file from inside the container."""
        code, out = self._run_in_container(["cat", path])
        if code == 0:
            return out.strip()
        return None

    def snapshot_capabilities(self) -> CapabilitySnapshot:
        """Capture capability state from /proc/self/status."""
        status = self._read_file_in_container("/proc/self/status") or ""

        cap_eff = ""
        cap_prm = ""
        cap_inh = ""
        cap_bnd = ""
        cap_amb = ""
        seccomp_mode = ""
        no_new_privs = False
        securebits_val = ""

        for line in status.split("\n"):
            if line.startswith("CapEff:"):
                cap_eff = line.split(":", 1)[1].strip()
            elif line.startswith("CapPrm:"):
                cap_prm = line.split(":", 1)[1].strip()
            elif line.startswith("CapInh:"):
                cap_inh = line.split(":", 1)[1].strip()
            elif line.startswith("CapBnd:"):
                cap_bnd = line.split(":", 1)[1].strip()
            elif line.startswith("CapAmb:"):
                cap_amb = line.split(":", 1)[1].strip()
            elif line.startswith("Seccomp:"):
                seccomp_mode = line.split(":", 1)[1].strip()
            elif line.startswith("NoNewPrivs:"):
                no_new_privs = line.split(":", 1)[1].strip() == "1"
            elif line.startswith("SecureBits:"):
                securebits_val = line.split(":", 1)[1].strip()

        return CapabilitySnapshot(
            cap_eff=cap_eff,
            cap_prm=cap_prm,
            cap_inh=cap_inh,
            cap_bnd=cap_bnd,
            cap_amb=cap_amb,
            securebits=securebits_val,
            seccomp_mode=seccomp_mode,
            no_new_privs=no_new_privs
        )

    def snapshot_cgroups(self) -> CgroupSnapshot:
        """Capture cgroup state."""
        cgroup_path = self._read_file_in_container("/proc/self/cgroup") or ""

        cgroup_version = "v1"
        if "0::" in cgroup_path or "cgroup.controllers" in cgroup_path:
            cgroup_version = "v2"

        controllers = []
        controllers_file = self._read_file_in_container("/sys/fs/cgroup/cgroup.controllers")
        if controllers_file:
            controllers = controllers_file.split()

        cpu_limit = self._read_file_in_container("/sys/fs/cgroup/cpu.max")
        memory_limit = self._read_file_in_container("/sys/fs/cgroup/memory.max")
        pids_limit = self._read_file_in_container("/sys/fs/cgroup/pids.max")

        cgroup_procs = self._read_file_in_container("/sys/fs/cgroup/cgroup.procs")
        procs_count = len(cgroup_procs.split("\n")) if cgroup_procs else 0

        return CgroupSnapshot(
            cgroup_path=cgroup_path,
            cgroup_version=cgroup_version,
            controllers=controllers,
            cpu_limit=cpu_limit,
            memory_limit=memory_limit,
            pids_limit=pids_limit,
            cgroup_procs_count=procs_count
        )

    def snapshot_namespaces(self) -> NamespaceSnapshot:
        """Capture namespace inode numbers."""

        def get_ns_inode(ns_type: str) -> str:
            # ns files are magic symlinks, not regular files — cat returns ""
            code, out = self._run_in_container(["readlink", f"/proc/self/ns/{ns_type}"])
            return out.strip() if code == 0 else ""

        return NamespaceSnapshot(
            pid_ns=get_ns_inode("pid"),
            mnt_ns=get_ns_inode("mnt"),
            net_ns=get_ns_inode("net"),
            uts_ns=get_ns_inode("uts"),
            ipc_ns=get_ns_inode("ipc"),
            user_ns=get_ns_inode("user"),
            cgroup_ns=get_ns_inode("cgroup"),
            time_ns=get_ns_inode("time")
        )

    def snapshot_proc(self) -> ProcSnapshot:
        """Capture process info."""
        status = self._read_file_in_container("/proc/self/status") or ""
        cmdline = self._read_file_in_container("/proc/self/cmdline") or ""
        exe_link = self._read_file_in_container("/proc/self/exe") or ""
        root_link = self._read_file_in_container("/proc/self/root") or ""

        pid = 0
        ppid = 0
        uid = 0
        gid = 0

        for line in status.split("\n"):
            if line.startswith("Pid:"):
                try:
                    pid = int(line.split(":", 1)[1].strip())
                except ValueError:
                    pass
            elif line.startswith("PPid:"):
                try:
                    ppid = int(line.split(":", 1)[1].strip())
                except ValueError:
                    pass
            elif line.startswith("Uid:"):
                try:
                    uid = int(line.split(":", 1)[1].split()[0])
                except (ValueError, IndexError):
                    pass
            elif line.startswith("Gid:"):
                try:
                    gid = int(line.split(":", 1)[1].split()[0])
                except (ValueError, IndexError):
                    pass

        mounts = self._read_file_in_container("/proc/self/mounts") or ""
        mounted_procs = []
        mounted_sys = False
        host_pid_visible = False

        for line in mounts.split("\n"):
            parts = line.split()
            if not parts:
                continue
            if parts[0] == "proc":
                mounted_procs.append(line)
            if parts[0] == "sysfs" or parts[0] == "sysfs_boot":
                mounted_sys = True

        # Host PID visibility: container shares the host PID namespace when its
        # pid_ns inode matches the host's /proc/1/ns/pid (readable from the host
        # side where this tool runs). A rw /proc mount alone does NOT imply it.
        host_pid_visible = False
        try:
            code, container_pid_ns = self._run_in_container(["readlink", "/proc/self/ns/pid"])
            host_pid_ns = os.readlink("/proc/1/ns/pid")
            if code == 0 and container_pid_ns.strip() and container_pid_ns.strip() == host_pid_ns:
                host_pid_visible = True
        except OSError:
            pass

        return ProcSnapshot(
            pid=pid,
            ppid=ppid,
            uid=uid,
            gid=gid,
            cmdline=cmdline[:200],
            exe_link=exe_link,
            root_link=root_link,
            mounted_procs=mounted_procs[:10],
            mounted_sys=mounted_sys,
            host_pid_visible=host_pid_visible
        )

    def snapshot_mounts(self) -> MountSnapshot:
        """Capture mount-related escape surfaces."""
        mounts = self._read_file_in_container("/proc/self/mounts") or ""

        docker_sock = False
        containerd_sock = False
        cri_o_sock = False
        host_root = False
        host_proc = False
        host_sys = False
        sensitive_mounts = []
        read_only_rootfs = False

        for line in mounts.split("\n"):
            parts = line.split()
            if len(parts) < 2:
                continue
            source, target = parts[0], parts[1]
            fstype = parts[2] if len(parts) > 2 else ""

            if "/var/run/docker.sock" in source:
                docker_sock = True
                sensitive_mounts.append("docker.sock")
            if "containerd.sock" in source:
                containerd_sock = True
                sensitive_mounts.append("containerd.sock")
            if "crio.sock" in source:
                cri_o_sock = True
                sensitive_mounts.append("crio.sock")
            if target == "/" and ",ro" in line:
                read_only_rootfs = True
            if target == "/host" or target == "/hostfs" or target.startswith("/host/") or target.startswith("/hostfs/"):
                host_root = True
                sensitive_mounts.append(f"host_path:{target}")
            # Classify by FILESYSTEM TYPE, not source: the container's own
            # /proc mounts as `proc /proc proc`, while a host /proc bind-mounted
            # elsewhere reads `/proc /host/proc proc`. Keying on the source
            # field missed every bind-mounted host proc/sys.
            if fstype == "proc" and target != "/proc":
                host_proc = True
                sensitive_mounts.append(f"host_proc:{target}")
            if fstype in ("sysfs", "sysfs_boot") and target != "/sys":
                host_sys = True
                sensitive_mounts.append(f"host_sys:{target}")

        return MountSnapshot(
            docker_sock=docker_sock,
            containerd_sock=containerd_sock,
            cri_o_sock=cri_o_sock,
            host_root=host_root,
            host_proc=host_proc,
            host_sys=host_sys,
            sensitive_mounts=sensitive_mounts,
            read_only_rootfs=read_only_rootfs
        )

    def capture(self, previous_hash: Optional[str] = None) -> RuntimeSnapshot:
        """Capture full runtime snapshot."""
        timestamp = datetime.now(timezone.utc).isoformat()

        snapshot = RuntimeSnapshot(
            timestamp=timestamp,
            container_id=self.container_id,
            capabilities=self.snapshot_capabilities(),
            cgroups=self.snapshot_cgroups(),
            namespaces=self.snapshot_namespaces(),
            proc=self.snapshot_proc(),
            mounts=self.snapshot_mounts(),
            hash_chain="",
            previous_hash=previous_hash
        )

        snapshot_data = json.dumps(asdict(snapshot), sort_keys=True, default=str)
        chain_input = (previous_hash or "") + snapshot_data
        snapshot.hash_chain = hashlib.sha256(chain_input.encode()).hexdigest()

        return snapshot


class DriftDetector:
    """Detect drift between baseline and current snapshot."""

    def __init__(self, baseline: RuntimeSnapshot):
        self.baseline = baseline

    def detect(self, current: RuntimeSnapshot) -> List[Dict[str, str]]:
        """Detect drift between baseline and current snapshot."""
        findings = []

        b_caps = self.baseline.capabilities
        c_caps = current.capabilities

        if b_caps.cap_eff != c_caps.cap_eff:
            findings.append({
                "level": "CRITICAL",
                "category": "capabilities",
                "description": f"Effective capabilities changed: {b_caps.cap_eff} -> {c_caps.cap_eff}",
                "remediation": "Investigate capability change; check for privilege escalation"
            })

        if b_caps.cap_bnd != c_caps.cap_bnd:
            findings.append({
                "level": "CRITICAL",
                "category": "capabilities",
                "description": f"Bounding set changed: {b_caps.cap_bnd} -> {c_caps.cap_bnd}",
                "remediation": "Bounding set cannot grow after exec; investigate container restart"
            })

        if b_caps.seccomp_mode != c_caps.seccomp_mode:
            findings.append({
                "level": "HIGH",
                "category": "seccomp",
                "description": f"Seccomp mode changed: {b_caps.seccomp_mode} -> {c_caps.seccomp_mode}",
                "remediation": "Investigate seccomp profile bypass"
            })

        if b_caps.no_new_privs != c_caps.no_new_privs:
            findings.append({
                "level": "HIGH",
                "category": "seccomp",
                "description": f"no_new_privs changed: {b_caps.no_new_privs} -> {c_caps.no_new_privs}",
                "remediation": "no_new_privs cannot be unset; investigate process replacement"
            })

        b_cg = self.baseline.cgroups
        c_cg = current.cgroups

        if b_cg.cgroup_path != c_cg.cgroup_path:
            findings.append({
                "level": "HIGH",
                "category": "cgroup",
                "description": f"Cgroup path changed: {b_cg.cgroup_path} -> {c_cg.cgroup_path}",
                "remediation": "Container may have been moved between cgroups"
            })

        if b_cg.cgroup_version != c_cg.cgroup_version:
            findings.append({
                "level": "HIGH",
                "category": "cgroup",
                "description": f"Cgroup version changed: {b_cg.cgroup_version} -> {c_cg.cgroup_version}",
                "remediation": "Cgroup hierarchy change indicates runtime modification"
            })

        b_ns = self.baseline.namespaces
        c_ns = current.namespaces

        for ns_name in ["pid_ns", "mnt_ns", "net_ns", "uts_ns", "ipc_ns", "user_ns", "cgroup_ns", "time_ns"]:
            b_val = getattr(b_ns, ns_name)
            c_val = getattr(c_ns, ns_name)
            if b_val != c_val:
                findings.append({
                    "level": "CRITICAL",
                    "category": "namespace",
                    "description": f"{ns_name} changed: {b_val} -> {c_val}",
                    "remediation": "Namespace escape detected; container may have joined host namespace"
                })

        b_m = self.baseline.mounts
        c_m = current.mounts

        if not b_m.docker_sock and c_m.docker_sock:
            findings.append({
                "level": "CRITICAL",
                "category": "mount",
                "description": "Docker socket newly mounted",
                "remediation": "Investigate docker.sock mount injection"
            })

        if not b_m.containerd_sock and c_m.containerd_sock:
            findings.append({
                "level": "CRITICAL",
                "category": "mount",
                "description": "containerd socket newly mounted",
                "remediation": "Investigate containerd.sock mount injection"
            })

        if not b_m.host_root and c_m.host_root:
            findings.append({
                "level": "CRITICAL",
                "category": "mount",
                "description": "Host root filesystem newly mounted",
                "remediation": "Investigate hostPath mount injection"
            })

        if not b_m.host_proc and c_m.host_proc:
            findings.append({
                "level": "HIGH",
                "category": "mount",
                "description": "Host /proc newly mounted",
                "remediation": "Investigate proc mount injection"
            })

        b_p = self.baseline.proc
        c_p = current.proc

        if b_p.exe_link != c_p.exe_link:
            findings.append({
                "level": "MEDIUM",
                "category": "process",
                "description": f"Executable changed: {b_p.exe_link} -> {c_p.exe_link}",
                "remediation": "Check for process replacement or injection"
            })

        if current.previous_hash != self.baseline.hash_chain:
            findings.append({
                "level": "CRITICAL",
                "category": "integrity",
                "description": f"Hash chain broken: previous={str(current.previous_hash)[:16]}... "
                               f"expected={self.baseline.hash_chain[:16]}...",
                "remediation": "Integrity violation detected in runtime state chain"
            })

        return findings


def snapshot_from_dict(data: dict) -> RuntimeSnapshot:
    """Reconstruct nested dataclasses from a JSON-loaded dict."""
    return RuntimeSnapshot(
        timestamp=data.get("timestamp", ""),
        container_id=data.get("container_id", ""),
        capabilities=CapabilitySnapshot(**data.get("capabilities", {})),
        cgroups=CgroupSnapshot(**data.get("cgroups", {})),
        namespaces=NamespaceSnapshot(**data.get("namespaces", {})),
        proc=ProcSnapshot(**data.get("proc", {})),
        mounts=MountSnapshot(**data.get("mounts", {})),
        hash_chain=data.get("hash_chain", ""),
        previous_hash=data.get("previous_hash"),
    )


def main():
    parser = argparse.ArgumentParser(description="Container Runtime Drift Baseline")
    subparsers = parser.add_subparsers(dest="command", required=True)

    baseline_parser = subparsers.add_parser("baseline", help="Take baseline snapshot")
    baseline_parser.add_argument("--container", required=True, help="Container ID or name")
    baseline_parser.add_argument("--output", default="baseline.json", help="Output file")
    baseline_parser.add_argument("--runtime", choices=["docker", "podman", "crictl"], default="docker")

    verify_parser = subparsers.add_parser("verify", help="Verify current state against baseline")
    verify_parser.add_argument("--container", required=True, help="Container ID or name")
    verify_parser.add_argument("--baseline", required=True, help="Baseline file")
    verify_parser.add_argument("--runtime", choices=["docker", "podman", "crictl"], default="docker")
    verify_parser.add_argument("--output", help="Output JSON file for findings")

    monitor_parser = subparsers.add_parser("monitor", help="Continuously monitor for drift")
    monitor_parser.add_argument("--container", required=True, help="Container ID or name")
    monitor_parser.add_argument("--baseline", required=True, help="Baseline file")
    monitor_parser.add_argument("--interval", type=int, default=30, help="Monitoring interval in seconds")
    monitor_parser.add_argument("--runtime", choices=["docker", "podman", "crictl"], default="docker")
    monitor_parser.add_argument("--output", help="Output JSON file for findings")

    args = parser.parse_args()

    use_docker = args.runtime == "docker"
    use_podman = args.runtime == "podman"
    use_crictl = args.runtime == "crictl"

    baseline = RuntimeBaseline(args.container, use_docker, use_podman, use_crictl)

    if args.command == "baseline":
        print(f"[*] Taking baseline snapshot of {args.container}...")
        snapshot = baseline.capture()

        with open(args.output, "w") as f:
            json.dump(asdict(snapshot), f, indent=2, default=str)

        print(f"[+] Baseline saved to {args.output}")
        print(f"[+] Hash chain: {snapshot.hash_chain[:32]}...")

        print("\n[Security Posture]")
        caps = snapshot.capabilities
        cap_eff_hex = int(caps.cap_eff, 16) if caps.cap_eff else 0
        dangerous_caps_present = []
        for i in range(64):
            if cap_eff_hex & (1 << i):
                cap_name = f"cap_{i}"
                if cap_name in RuntimeBaseline.DANGEROUS_CAPS:
                    dangerous_caps_present.append(cap_name)

        if dangerous_caps_present:
            print(f"[!] Dangerous capabilities present: {', '.join(dangerous_caps_present)}")
        else:
            print("[+] No dangerous capabilities in effective set")

        if snapshot.mounts.docker_sock:
            print("[!] Docker socket mounted - CRITICAL escape risk")
        if snapshot.mounts.containerd_sock:
            print("[!] containerd socket mounted - CRITICAL escape risk")
        if snapshot.mounts.host_root:
            print("[!] Host root mounted - CRITICAL escape risk")
        if snapshot.proc.host_pid_visible:
            print("[!] Host PIDs visible - HIGH escape risk")

        if not snapshot.mounts.read_only_rootfs:
            print("[i] Root filesystem is writable")

        print("[i] Snapshot complete")

    elif args.command == "verify":
        print(f"[*] Verifying {args.container} against {args.baseline}...")

        with open(args.baseline, "r") as f:
            baseline_data = json.load(f)

        baseline_snapshot = snapshot_from_dict(baseline_data)
        current_snapshot = baseline.capture(previous_hash=baseline_snapshot.hash_chain)

        detector = DriftDetector(baseline_snapshot)
        findings = detector.detect(current_snapshot)

        if findings:
            print(f"[!] Detected {len(findings)} drift findings:")
            for i, finding in enumerate(findings, 1):
                print(f"\n{i}. [{finding['level']}] {finding['category']}")
                print(f"   {finding['description']}")
                print(f"   Remediation: {finding['remediation']}")
        else:
            print("[+] No drift detected - container state matches baseline")

        if args.output:
            with open(args.output, "w") as f:
                json.dump({
                    "verified": len(findings) == 0,
                    "findings": findings,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }, f, indent=2, default=str)
            print(f"\n[+] Findings written to {args.output}")

    elif args.command == "monitor":
        print(f"[*] Monitoring {args.container} every {args.interval}s...")
        print("[*] Press Ctrl+C to stop")

        with open(args.baseline, "r") as f:
            baseline_data = json.load(f)

        baseline_snapshot = snapshot_from_dict(baseline_data)

        all_findings = []

        def signal_handler(sig, frame):
            print("\n[*] Stopping monitor...")
            if args.output and all_findings:
                with open(args.output, "w") as f:
                    json.dump(all_findings, f, indent=2, default=str)
                print(f"[+] Findings written to {args.output}")
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        while True:
            try:
                current_snapshot = baseline.capture(previous_hash=baseline_snapshot.hash_chain)
                # Compare against the rolling baseline (previous snapshot), not the original
                detector = DriftDetector(baseline_snapshot)
                findings = detector.detect(current_snapshot)

                timestamp = datetime.now().strftime("%H:%M:%S")
                if findings:
                    for finding in findings:
                        print(f"[{timestamp}] [{finding['level']}] {finding['category']}: {finding['description']}")
                        all_findings.append({
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            **finding
                        })
                else:
                    print(f"[{timestamp}] No drift detected")

                baseline_snapshot = current_snapshot
                time.sleep(args.interval)
            except KeyboardInterrupt:
                signal_handler(None, None)


if __name__ == "__main__":
    main()
