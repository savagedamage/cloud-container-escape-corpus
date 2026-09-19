"""Tests for escape_corpus.image_diff — synthetic OCI images, no registry needed.

Fixtures reproduce the exact `crane pull` layout: an outer tar holding
`manifest.json` + a config blob + one gzipped layer tar per filesystem layer.
"""

import gzip
import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest

from escape_corpus.image_diff import (
    assess_file_risk,
    compute_risk_level,
    diff_configs,
    diff_filesystems,
    flatten_image_tar,
    get_file_sha256,
    is_elf_binary,
    pull_image_tar,
    safe_extract_layer,
)

ELF = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56          # minimal ELF-ish header
SCRIPT = b"#!/bin/sh\necho hi\n"


def _layer_bytes(files=None, symlinks=None, hardlinks=None) -> bytes:
    """Build a gzipped layer tar (regular files, symlinks, hardlinks).

    Names are normalised to relative form — real OCI layers never store a
    leading slash, and `safe_extract_layer` (correctly) refuses absolute
    members, so passing "/bin/app" here would silently extract nothing.
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, spec in (files or {}).items():
            data, mode = spec if isinstance(spec, tuple) else (spec, 0o644)
            info = tarfile.TarInfo(name.lstrip("/"))
            info.size = len(data)
            info.mode = mode
            tf.addfile(info, io.BytesIO(data))
        for name, target in (symlinks or {}).items():
            info = tarfile.TarInfo(name.lstrip("/"))
            info.type = tarfile.SYMTYPE
            info.linkname = target
            tf.addfile(info)
        for name, target in (hardlinks or {}).items():
            info = tarfile.TarInfo(name.lstrip("/"))
            info.type = tarfile.LNKTYPE
            info.linkname = target.lstrip("/")
            tf.addfile(info)
    return gzip.compress(buf.getvalue())


def build_image_tar(out: Path, layers, config=None) -> Path:
    """Write a crane-style image tar: manifest.json + config blob + layer blobs."""
    config = config or {"config": {"Cmd": ["/bin/sh"], "Env": ["PATH=/usr/bin"]},
                        "architecture": "amd64", "os": "linux"}
    config_bytes = json.dumps(config).encode()
    config_name = "sha256:" + hashlib.sha256(config_bytes).hexdigest()

    blobs = []
    for i, layer in enumerate(layers):
        data = _layer_bytes(**layer)
        blobs.append((f"{i:02d}-layer.tar.gz", data))

    manifest = [{"Config": config_name,
                 "RepoTags": ["test:latest"],
                 "Layers": [b[0] for b in blobs]}]

    with tarfile.open(out, "w") as tf:
        info = tarfile.TarInfo(config_name)
        info.size = len(config_bytes)
        tf.addfile(info, io.BytesIO(config_bytes))
        for name, data in blobs:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        mdata = json.dumps(manifest).encode()
        info = tarfile.TarInfo("manifest.json")
        info.size = len(mdata)
        tf.addfile(info, io.BytesIO(mdata))
    return out


@pytest.fixture
def old_image(tmp_path):
    return build_image_tar(
        tmp_path / "old.tar",
        [
            {"files": {"/bin/app": (ELF, 0o755), "/etc/shadow": b"root:!:1", "/etc/keep": b"same"}},
        ],
        config={"config": {"Cmd": ["/bin/sh"], "User": "0", "Env": ["PATH=/usr/bin", "TAG=1"]}},
    )


@pytest.fixture
def new_image(tmp_path):
    return build_image_tar(
        tmp_path / "new.tar",
        [
            {"files": {"/bin/app": (ELF, 0o755), "/etc/shadow": b"root:!:2", "/etc/keep": b"same"}},
            {"files": {"/bin/added": (ELF, 0o4755), "/opt/run.sh": (SCRIPT, 0o755)},
             "symlinks": {"/bin/link": "/bin/app"}},
        ],
        config={"config": {"Cmd": ["/bin/sh", "-c"], "User": "1000",
                           "Env": ["PATH=/usr/bin", "TAG=2", "API_TOKEN=" + "x" * 12]}},
    )


class TestFlatten:
    def test_records_files_symlinks_and_modes(self, old_image, tmp_path):
        flat, layers, merge = flatten_image_tar(old_image, tmp_path / "w")
        assert len(layers) == 1
        assert flat["/bin/app"]["type"] == "file"
        assert flat["/bin/app"]["mode"] & 0o111          # executable bit preserved
        assert flat["/etc/keep"]["sha256"] == hashlib.sha256(b"same").hexdigest()

    def test_later_layer_wins_on_merge(self, tmp_path):
        img = build_image_tar(tmp_path / "t.tar", [
            {"files": {"/etc/conf": b"layer1"}},
            {"files": {"/etc/conf": b"layer2"}},
        ])
        flat, _, _ = flatten_image_tar(img, tmp_path / "w")
        assert flat["/etc/conf"]["sha256"] == hashlib.sha256(b"layer2").hexdigest()

    def test_symlink_recorded_by_target_not_content(self, new_image, tmp_path):
        flat, _, _ = flatten_image_tar(new_image, tmp_path / "w")
        assert flat["/bin/link"]["type"] == "symlink"
        assert flat["/bin/link"]["target"] == "/bin/app"

    def test_hardlinks_recorded_by_target(self, tmp_path):
        img = build_image_tar(tmp_path / "t.tar", [
            {"files": {"/bin/busybox": (ELF, 0o755)},
             "hardlinks": {"/bin/ls": "/bin/busybox", "/bin/cat": "/bin/busybox"}},
        ])
        flat, _, _ = flatten_image_tar(img, tmp_path / "w")
        assert flat["/bin/ls"]["type"] == "hardlink"
        assert flat["/bin/ls"]["target"] == "/bin/busybox"

    def test_missing_manifest_is_an_error(self, tmp_path):
        bad = tmp_path / "bad.tar"
        with tarfile.open(bad, "w") as tf:
            info = tarfile.TarInfo("nope.txt")
            info.size = 1
            tf.addfile(info, io.BytesIO(b"x"))
        with pytest.raises(RuntimeError, match="manifest.json"):
            flatten_image_tar(bad, tmp_path / "w")

    def test_absolute_and_parent_paths_do_not_escape(self, tmp_path):
        """Containment: a hostile layer must not write outside the merge dir."""
        dest = tmp_path / "dest"
        dest.mkdir()
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            for name in ("/tmp/absolute-escape", "../../parent-escape"):
                info = tarfile.TarInfo(name)
                info.size = 4
                tf.addfile(info, io.BytesIO(b"pwnd"))
        buf.seek(0)
        with tarfile.open(fileobj=buf) as lt:
            safe_extract_layer(lt, dest)
        assert not Path("/tmp/absolute-escape").exists()
        assert not (tmp_path / "parent-escape").exists()
        assert not (dest.parent / "parent-escape").exists()


class TestDiff:
    def test_counts_and_change_kinds(self, old_image, new_image, tmp_path):
        old_flat, _, _ = flatten_image_tar(old_image, tmp_path / "w1")
        new_flat, _, new_merge = flatten_image_tar(new_image, tmp_path / "w2")
        changes, binaries, caps = diff_filesystems(old_flat, new_flat, new_merge)

        by_type = {}
        for c in changes:
            by_type.setdefault(c.change_type, []).append(c.path)
        assert "/bin/added" in by_type["added"]
        assert "/opt/run.sh" in by_type["added"]
        assert "/etc/shadow" in by_type["modified"]
        assert "/etc/keep" not in [p for v in by_type.values() for p in v]
        assert "/bin/added" in binaries

    def test_setuid_and_sensitive_paths_are_scored(self, old_image, new_image, tmp_path):
        old_flat, _, _ = flatten_image_tar(old_image, tmp_path / "w1")
        new_flat, _, new_merge = flatten_image_tar(new_image, tmp_path / "w2")
        changes, _, _ = diff_filesystems(old_flat, new_flat, new_merge)
        added = {c.path: c for c in changes if c.change_type == "added"}
        assert "setuid" in added["/bin/added"].risk_factors
        assert added["/bin/added"].risk_score >= 40
        shadow = next(c for c in changes if c.path == "/etc/shadow")
        assert "sensitive_path_modified" in shadow.risk_factors

    def test_hardlink_target_change_only_counts_the_target(self, tmp_path):
        """busybox-style applets: unchanged hardlinks must not be 'modified'."""
        old = build_image_tar(tmp_path / "o.tar", [
            {"files": {"/bin/bb": b"v1"}, "hardlinks": {"/bin/ls": "/bin/bb"}}])
        new = build_image_tar(tmp_path / "n.tar", [
            {"files": {"/bin/bb": b"v2"}, "hardlinks": {"/bin/ls": "/bin/bb"}}])
        of, _, _ = flatten_image_tar(old, tmp_path / "w1")
        nf, _, merge = flatten_image_tar(new, tmp_path / "w2")
        changes, _, _ = diff_filesystems(of, nf, merge)
        modified = [c.path for c in changes if c.change_type == "modified"]
        assert "/bin/bb" in modified
        assert "/bin/ls" not in modified      # same target -> unchanged


class TestRiskHelpers:
    @pytest.mark.parametrize("score,level", [
        (0, "LOW"), (19, "LOW"), (20, "MEDIUM"), (49, "MEDIUM"),
        (50, "HIGH"), (99, "HIGH"), (100, "CRITICAL"), (500, "CRITICAL"),
    ])
    def test_risk_level_thresholds(self, score, level):
        assert compute_risk_level(score) == level

    def test_elf_detection(self, tmp_path):
        p = tmp_path / "elf"
        p.write_bytes(ELF)
        assert is_elf_binary(p)
        q = tmp_path / "text"
        q.write_bytes(b"hello")
        assert not is_elf_binary(q)

    def test_sha256_matches_hashlib(self, tmp_path):
        p = tmp_path / "f"
        p.write_bytes(b"abc")
        assert get_file_sha256(p) == hashlib.sha256(b"abc").hexdigest()

    def test_executable_but_not_elf_still_flagged_as_binary(self):
        score, factors = assess_file_risk("/usr/local/bin/tool", "added", 10, 0o755, None)
        assert "new_binary" in factors and score > 0

    def test_certificate_and_ssh_key_additions(self):
        _, f1 = assess_file_risk("/etc/ssl/private/site.key", "added", 10, 0o600, None)
        assert "certificate_key" in f1
        _, f2 = assess_file_risk("/root/.ssh/id_rsa", "added", 10, 0o600, None)
        assert "ssh_key" in f2

    def test_large_file_factor(self):
        _, factors = assess_file_risk("/opt/blob", "added", 60 * 1024 * 1024, 0o644, None)
        assert any(f.startswith("large_file") for f in factors)


class TestConfigDiff:
    def test_detects_cmd_user_and_env_changes(self):
        old = {"config": {"Cmd": ["/bin/sh"], "User": "0",
                          "Env": ["PATH=/usr/bin", "TAG=1"]}}
        new = {"config": {"Cmd": ["/bin/sh", "-c"], "User": "1000",
                          "Env": ["PATH=/usr/bin", "TAG=2", "TOKEN=abc"]}}
        entrypoint, cmd, user, env = diff_configs(old, new)
        assert cmd is True and user is True and entrypoint is False
        assert env["TAG"] == ["1", "2"]
        assert env["TOKEN"] == [None, "abc"]

    def test_identical_configs_report_no_change(self):
        cfg = {"config": {"Cmd": ["/bin/sh"], "Env": ["A=1"]}}
        assert diff_configs(cfg, cfg) == (False, False, False, {})

    def test_missing_config_sections_are_tolerated(self):
        assert diff_configs({}, {}) == (False, False, False, {})


class TestPullGuard:
    def test_unavailable_registry_tool_raises(self, tmp_path, monkeypatch):
        import escape_corpus.image_diff as m
        monkeypatch.setattr(m, "CRANE", "")
        monkeypatch.setattr(m, "SKOPEO", "")
        with pytest.raises(RuntimeError, match="Failed to pull"):
            pull_image_tar("example:none", tmp_path / "x.tar")


class TestMainEntryPoint:
    """The CLI path users actually run, driven without touching a registry."""

    def _wire(self, monkeypatch, tmp_path, old_layers, new_layers, old_cfg, new_cfg):
        import escape_corpus.image_diff as m

        old_tar = build_image_tar(tmp_path / "old.tar", old_layers, config=old_cfg)
        new_tar = build_image_tar(tmp_path / "new.tar", new_layers, config=new_cfg)
        tars = {"old:1": old_tar, "new:2": new_tar}

        def fake_pull(image, dest):
            dest.write_bytes(tars[image].read_bytes())

        def fake_config(image):
            return {"config": old_cfg["config"] if image == "old:1" else new_cfg["config"]}

        monkeypatch.setattr(m, "pull_image_tar", fake_pull)
        monkeypatch.setattr(m, "get_image_config", fake_config)

    def test_reports_and_writes_json(self, monkeypatch, tmp_path, capsys):
        self._wire(
            monkeypatch, tmp_path,
            [{"files": {"/bin/app": (ELF, 0o755), "/etc/shadow": b"a"}}],
            [{"files": {"/bin/app": (ELF, 0o755), "/etc/shadow": b"b"}},
             {"files": {"/bin/suid": (ELF, 0o4755)}}],
            {"config": {"Cmd": ["/bin/sh"], "User": "0", "Env": ["A=1"]}},
            {"config": {"Cmd": ["/bin/sh", "-c"], "User": "1000", "Env": ["A=1", "TOKEN=zzz"]}},
        )
        out = tmp_path / "diff.json"
        import sys
        monkeypatch.setattr(sys, "argv",
                            ["image-diff", "old:1", "new:2", "-o", str(out), "-v"])
        import escape_corpus.image_diff as m
        m.main()

        text = capsys.readouterr().out
        assert "Image Diff Report" in text and "CRITICAL" in text or "MEDIUM" in text
        doc = json.loads(out.read_text())
        assert doc["image_old"] == "old:1" and doc["image_new"] == "new:2"
        assert doc["files_added"] >= 1
        assert doc["user_changed"] is True and doc["cmd_changed"] is True
        assert doc["env_changes"]["TOKEN"] == [None, "zzz"]
        assert doc["total_risk_score"] > 0
        assert "/bin/suid" in doc["new_binaries"]
