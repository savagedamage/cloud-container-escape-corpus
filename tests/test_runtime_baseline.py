"""Tests for escape_corpus.runtime_baseline.

The collector is exercised through a canned `_run_in_container` so snapshot
parsing (capabilities, cgroups, namespaces, mounts) is testable without a
container runtime. DriftDetector is then driven through its full branch matrix.
"""

import dataclasses
import json
import os

import pytest

from escape_corpus.runtime_baseline import (
    DriftDetector,
    RuntimeBaseline,
    RuntimeSnapshot,
    snapshot_from_dict,
)

STATUS = "\n".join([
    "Name:\tbash",
    "Pid:\t1",
    "PPid:\t0",
    "Uid:\t0\t0\t0\t0",
    "Gid:\t0\t0\t0\t0",
    "CapInh:\t0000000000000000",
    "CapPrm:\t00000000a80425fb",
    "CapEff:\t00000000a80425fb",
    "CapBnd:\t00000000a80425fb",
    "CapAmb:\t0000000000000000",
    "Seccomp:\t2",
    "NoNewPrivs:\t1",
    "SecureBits:\t0000000000000000",
])

MOUNTS = "\n".join([
    "overlay / overlay rw,relatime lowerdir=/var/lib/docker/overlay2/l/ABC",
    "proc /proc proc rw,nosuid,nodev,noexec,relatime",
    "sysfs /sys sysfs ro,nosuid,nodev,noexec,relatime",
    "shm /dev/shm tmpfs rw,nosuid,nodev,noexec",
    "/dev/sda1 /etc/hosts ext4 rw,relatime",
    "/var/run/docker.sock /var/run/docker.sock bind rw,relatime",
    "/proc /host/proc proc rw,relatime",
])

# Same table without any /host mount: used to prove that an /etc/hosts bind
# mount is not mistaken for a mounted host root.
MOUNTS_NO_HOST = "\n".join([
    "overlay / overlay rw,relatime lowerdir=/var/lib/docker/overlay2/l/ABC",
    "proc /proc proc rw,nosuid,nodev,noexec,relatime",
    "sysfs /sys sysfs ro,nosuid,nodev,noexec,relatime",
    "/dev/sda1 /etc/hosts ext4 rw,relatime",
    "/dev/sdb1 /etc/hostname ext4 rw,relatime",
])


@pytest.fixture
def make_collector(monkeypatch):
    """Factory: a RuntimeBaseline whose in-container exec is canned."""
    def _make(mounts=MOUNTS, files=None):
        calls = []
        table = {
            ("cat", "/proc/self/status"): STATUS,
            ("cat", "/proc/self/cgroup"): "0::/docker/abcdef",
            ("cat", "/sys/fs/cgroup/cgroup.controllers"): "cpu memory pids",
            ("cat", "/sys/fs/cgroup/cpu.max"): "100000 100000",
            ("cat", "/sys/fs/cgroup/memory.max"): "1073741824",
            ("cat", "/sys/fs/cgroup/pids.max"): "64",
            ("cat", "/sys/fs/cgroup/cgroup.procs"): "1\n42",
            ("cat", "/proc/self/cmdline"): "/bin/sh",
            ("cat", "/proc/self/exe"): "/usr/bin/sleep",
            ("cat", "/proc/self/root"): "/",
            ("cat", "/proc/self/mounts"): mounts,
            ("readlink", "/proc/self/ns/pid"): "pid:[4026531836]",
            ("readlink", "/proc/self/ns/mnt"): "mnt:[4026531841]",
            ("readlink", "/proc/self/ns/net"): "net:[4026531840]",
            ("readlink", "/proc/self/ns/uts"): "uts:[4026531838]",
            ("readlink", "/proc/self/ns/ipc"): "ipc:[4026531839]",
            ("readlink", "/proc/self/ns/user"): "user:[4026531837]",
            ("readlink", "/proc/self/ns/cgroup"): "cgroup:[4026531835]",
            ("readlink", "/proc/self/ns/time"): "time:[4026531834]",
        }
        if files:
            table.update(files)

        def fake_run(self, cmd):
            calls.append(tuple(cmd))
            return (0, table[tuple(cmd)]) if tuple(cmd) in table else (1, "")

        monkeypatch.setattr(RuntimeBaseline, "_run_in_container", fake_run)
        rb = RuntimeBaseline("test-container", use_docker=True)
        rb.calls = calls
        return rb
    return _make


@pytest.fixture
def collector(make_collector):
    return make_collector()


class TestSnapshotParsing:
    def test_capabilities_parsed(self, collector):
        caps = collector.snapshot_capabilities()
        assert caps.cap_eff == "00000000a80425fb"
        assert caps.cap_bnd == "00000000a80425fb"
        assert caps.seccomp_mode == "2"
        assert caps.no_new_privs is True

    def test_cgroup_v2_detected_with_limits(self, collector):
        cg = collector.snapshot_cgroups()
        assert cg.cgroup_version == "v2"
        assert cg.controllers == ["cpu", "memory", "pids"]
        assert cg.memory_limit == "1073741824"
        assert cg.cgroup_procs_count == 2      # "1\n42"

    def test_namespaces_read_with_readlink(self, collector):
        ns = collector.snapshot_namespaces()
        assert ns.pid_ns == "pid:[4026531836]"
        assert ns.mnt_ns.startswith("mnt:")
        assert ("readlink", "/proc/self/ns/pid") in collector.calls

    def test_proc_identity(self, collector):
        p = collector.snapshot_proc()
        assert (p.pid, p.ppid, p.uid, p.gid) == (1, 0, 0, 0)
        assert p.exe_link == "/usr/bin/sleep"

    def test_runtime_socket_mount_detected(self, collector):
        m = collector.snapshot_mounts()
        assert m.docker_sock is True

    def test_etc_hosts_is_not_a_host_root_mount(self, make_collector):
        """Regression: substring matching made every container's /etc/hosts
        bind mount look like a mounted host root."""
        m = make_collector(mounts=MOUNTS_NO_HOST).snapshot_mounts()
        assert m.host_root is False
        assert m.host_proc is False

    def test_host_proc_mount_detected(self, collector):
        m = collector.snapshot_mounts()
        assert m.host_proc is True          # proc at /host/proc, not /proc

    def test_host_pid_visible_only_when_inode_matches_host(self, collector, monkeypatch):
        # same inode as the host's pid namespace -> visible
        monkeypatch.setattr(os, "readlink", lambda p: "pid:[4026531836]")
        assert collector.snapshot_proc().host_pid_visible is True

        others = [c for c in collector.calls]
        monkeypatch.setattr(os, "readlink", lambda p: "pid:[4026539999]")
        assert collector.snapshot_proc().host_pid_visible is False
        assert others is not None

    def test_sensitive_mount_list_is_populated(self, collector):
        assert "docker.sock" in collector.snapshot_mounts().sensitive_mounts


class TestCaptureAndRoundTrip:
    def test_capture_is_hash_chained(self, collector):
        first = collector.capture()
        second = collector.capture(previous_hash=first.hash_chain)
        assert len(first.hash_chain) == 64
        assert second.previous_hash == first.hash_chain
        assert second.hash_chain != first.hash_chain

    def test_hash_chain_is_deterministic_for_same_input(self, collector, monkeypatch):
        """With the clock frozen, identical input must hash identically."""
        import datetime as _dt

        import escape_corpus.runtime_baseline as m

        class FixedDatetime(_dt.datetime):
            @classmethod
            def now(cls, tz=None):
                return _dt.datetime(2026, 9, 16, 12, 0, 0, tzinfo=tz)

        monkeypatch.setattr(m, "datetime", FixedDatetime)
        assert collector.capture().hash_chain == collector.capture().hash_chain

    def test_json_round_trip_rebuilds_dataclasses(self, collector):
        snap = collector.capture()
        restored = snapshot_from_dict(json.loads(json.dumps(dataclasses.asdict(snap), default=str)))
        assert isinstance(restored.capabilities, type(snap.capabilities))
        assert restored.capabilities.cap_eff == snap.capabilities.cap_eff
        assert restored.namespaces.pid_ns == snap.namespaces.pid_ns
        assert restored.mounts.docker_sock == snap.mounts.docker_sock
        # a round-tripped snapshot, correctly chained, must not look like drift
        chained = dataclasses.replace(restored, previous_hash=restored.hash_chain)
        assert DriftDetector(chained).detect(chained) == []


def _base_snapshot(collector) -> RuntimeSnapshot:
    return collector.capture()


class TestDriftDetectorMatrix:
    """Every detector branch, with its intended severity."""

    def _detect(self, collector, mutate):
        baseline = _base_snapshot(collector)
        current = dataclasses.replace(baseline, **mutate(baseline))
        return {f["category"]: f for f in DriftDetector(baseline).detect(current)}

    def test_capability_change_is_critical(self, collector):
        found = self._detect(collector, lambda b: {
            "capabilities": dataclasses.replace(b.capabilities, cap_eff="00000000a80c25fb")})
        assert found["capabilities"]["level"] == "CRITICAL"

    def test_bounding_set_change_is_critical(self, collector):
        found = self._detect(collector, lambda b: {
            "capabilities": dataclasses.replace(b.capabilities, cap_bnd="ffffffffffffffff")})
        assert found["capabilities"]["level"] == "CRITICAL"

    def test_seccomp_change_is_high(self, collector):
        found = self._detect(collector, lambda b: {
            "capabilities": dataclasses.replace(b.capabilities, seccomp_mode="0")})
        assert found["seccomp"]["level"] == "HIGH"

    def test_no_new_privs_flip_is_high(self, collector):
        found = self._detect(collector, lambda b: {
            "capabilities": dataclasses.replace(b.capabilities, no_new_privs=False)})
        assert found["seccomp"]["level"] == "HIGH"

    def test_cgroup_path_change_is_high(self, collector):
        found = self._detect(collector, lambda b: {
            "cgroups": dataclasses.replace(b.cgroups, cgroup_path="0::/system.slice")})
        assert found["cgroup"]["level"] == "HIGH"

    def test_namespace_change_is_critical(self, collector):
        found = self._detect(collector, lambda b: {
            "namespaces": dataclasses.replace(b.namespaces, net_ns="net:[1]")})
        assert found["namespace"]["level"] == "CRITICAL"

    def test_new_docker_socket_mount_is_critical(self, collector):
        baseline = _base_snapshot(collector)
        clean = dataclasses.replace(baseline, mounts=dataclasses.replace(baseline.mounts, docker_sock=False))
        current = dataclasses.replace(clean, mounts=dataclasses.replace(clean.mounts, docker_sock=True))
        found = {f["category"]: f for f in DriftDetector(clean).detect(current)}
        assert found["mount"]["level"] == "CRITICAL"

    def test_new_host_root_mount_is_critical(self, collector):
        baseline = _base_snapshot(collector)
        clean = dataclasses.replace(baseline, mounts=dataclasses.replace(baseline.mounts, host_root=False))
        current = dataclasses.replace(clean, mounts=dataclasses.replace(clean.mounts, host_root=True))
        found = {f["category"]: f for f in DriftDetector(clean).detect(current)}
        assert found["mount"]["level"] == "CRITICAL"

    def test_executable_change_is_medium(self, collector):
        found = self._detect(collector, lambda b: {
            "proc": dataclasses.replace(b.proc, exe_link="/usr/bin/curl")})
        assert found["process"]["level"] == "MEDIUM"

    def test_broken_hash_chain_is_critical(self, collector):
        baseline = _base_snapshot(collector)
        current = dataclasses.replace(baseline, previous_hash="f" * 64)
        found = {f["category"]: f for f in DriftDetector(baseline).detect(current)}
        assert found["integrity"]["level"] == "CRITICAL"

    def test_clean_snapshot_yields_no_findings(self, collector):
        baseline = _base_snapshot(collector)
        # a correctly chained re-capture of identical state is not drift
        current = dataclasses.replace(baseline, previous_hash=baseline.hash_chain)
        assert DriftDetector(baseline).detect(current) == []

    def test_monitor_rolling_baseline_does_not_false_positive(self, collector):
        """Monitor rebuilds the detector against the previous snapshot each tick;
        doing so must not report a hash-chain break."""
        first = collector.capture()
        second = collector.capture(previous_hash=first.hash_chain)
        findings = DriftDetector(second).detect(
            collector.capture(previous_hash=second.hash_chain))
        assert [f for f in findings if f["category"] == "integrity"] == []


class TestCgroupV1:
    """cgroup v1 hosts read their limits from entirely different paths.

    Regression: v1 was *detected* but never read — every limit came back None, so
    resource-limit drift was invisible on v1 nodes.
    """

    # v1 has no cgroup.controllers/cpu.max/...; the v2 keys are blanked so only
    # the v1 paths can satisfy the reader.
    V1_FILES = {
        ("cat", "/proc/self/cgroup"): (
            "11:memory:/docker/abcdef\n"
            "10:cpu,cpuacct:/docker/abcdef\n"
            "9:pids:/docker/abcdef\n"
            "1:name=systemd:/docker/abcdef"
        ),
        ("cat", "/sys/fs/cgroup/cgroup.controllers"): "",
        ("cat", "/sys/fs/cgroup/cpu.max"): "",
        ("cat", "/sys/fs/cgroup/memory.max"): "",
        ("cat", "/sys/fs/cgroup/pids.max"): "",
        ("cat", "/sys/fs/cgroup/cgroup.procs"): "",
        ("cat", "/sys/fs/cgroup/cpu/cpu.cfs_quota_us"): "50000",
        ("cat", "/sys/fs/cgroup/cpu/cpu.cfs_period_us"): "100000",
        ("cat", "/sys/fs/cgroup/memory/memory.limit_in_bytes"): "536870912",
        ("cat", "/sys/fs/cgroup/pids/pids.max"): "128",
        ("cat", "/sys/fs/cgroup/pids/cgroup.procs"): "1\n42\n43",
    }

    def test_version_and_path_are_detected(self, make_collector):
        snap = make_collector(files=self.V1_FILES).capture().cgroups
        assert snap.cgroup_version == "v1"
        assert snap.cgroup_path.startswith("11:memory:")

    def test_limits_are_read_from_v1_paths(self, make_collector):
        snap = make_collector(files=self.V1_FILES).capture().cgroups
        assert snap.memory_limit == "536870912"
        assert snap.pids_limit == "128"
        # v1 quota+period expressed in the v2 "quota period" shape
        assert snap.cpu_limit == "50000 100000"

    def test_controllers_come_from_proc_self_cgroup(self, make_collector):
        snap = make_collector(files=self.V1_FILES).capture().cgroups
        assert {"memory", "cpu", "cpuacct", "pids"} <= set(snap.controllers)

    def test_unlimited_cpu_quota_maps_to_max(self, make_collector):
        files = {**self.V1_FILES,
                 ("cat", "/sys/fs/cgroup/cpu/cpu.cfs_quota_us"): "-1"}
        snap = make_collector(files=files).capture().cgroups
        assert snap.cpu_limit == "max"

    def test_procs_count_uses_the_v1_pids_controller(self, make_collector):
        snap = make_collector(files=self.V1_FILES).capture().cgroups
        assert snap.cgroup_procs_count == 3

    def test_memory_limit_change_on_v1_is_detected_as_drift(self, make_collector):
        """The finding that motivates the fix: on v1, a silent limit change used to
        compare None == None and never fire."""
        baseline = make_collector(files=self.V1_FILES).capture()
        tightened = {**self.V1_FILES,
                     ("cat", "/sys/fs/cgroup/memory/memory.limit_in_bytes"): "268435456"}
        current = make_collector(files=tightened).capture()
        current.previous_hash = baseline.hash_chain

        findings = DriftDetector(baseline).detect(current)
        assert any(f["category"] == "cgroup" for f in findings), [f["category"] for f in findings]

    def test_no_drift_when_v1_state_is_unchanged(self, make_collector):
        baseline = make_collector(files=self.V1_FILES).capture()
        current = make_collector(files=self.V1_FILES).capture()
        current.previous_hash = baseline.hash_chain
        assert DriftDetector(baseline).detect(current) == []


class TestCliMain:
    """The three CLI verbs, exercised end to end against the canned collector."""

    def _run(self, monkeypatch, argv, collector):
        import sys

        import escape_corpus.runtime_baseline as m

        # main() constructs its own RuntimeBaseline; route any instance to the
        # canned collector by calling the ORIGINAL capture on that instance
        # (binding the patched method to itself would recurse).
        orig_capture = m.RuntimeBaseline.capture
        monkeypatch.setattr(m.RuntimeBaseline, "capture",
                            lambda self, previous_hash=None: orig_capture(collector, previous_hash))
        monkeypatch.setattr(sys, "argv", ["runtime-baseline"] + argv)
        return m.main()

    def test_baseline_writes_snapshot_and_posture(self, collector, tmp_path, monkeypatch, capsys):
        out = tmp_path / "baseline.json"
        self._run(monkeypatch, ["baseline", "--container", "c1", "--runtime", "docker",
                                "--output", str(out)], collector)
        text = capsys.readouterr().out
        assert "Baseline saved" in text and "Security Posture" in text
        doc = json.loads(out.read_text())
        # the snapshot comes from the canned collector, so it carries that id
        assert doc["container_id"] and len(doc["hash_chain"]) == 64
        assert doc["capabilities"]["cap_eff"] == "00000000a80425fb"

    def test_verify_reports_no_drift_for_matching_state(self, collector, tmp_path, monkeypatch, capsys):
        base = tmp_path / "b.json"
        self._run(monkeypatch, ["baseline", "--container", "c1", "--output", str(base)], collector)
        capsys.readouterr()

        # make the baseline look like the immediately preceding snapshot so the
        # chain links correctly (capture() re-stamps a fresh timestamp)
        import dataclasses
        doc = json.loads(base.read_text())
        snap = collector.capture()
        doc.update({k: v for k, v in dataclasses.asdict(snap).items()})
        doc["previous_hash"] = snap.hash_chain
        doc["hash_chain"] = snap.hash_chain
        base.write_text(json.dumps(doc, default=str))

        self._run(monkeypatch, ["verify", "--container", "c1", "--baseline", str(base)], collector)
        assert "No drift detected" in capsys.readouterr().out

    def test_monitor_loop_runs_and_stops_cleanly(self, collector, tmp_path, monkeypatch, capsys):
        base = tmp_path / "b.json"
        self._run(monkeypatch, ["baseline", "--container", "c1", "--output", str(base)], collector)
        capsys.readouterr()

        import escape_corpus.runtime_baseline as m
        ticks = {"n": 0}

        def fake_sleep(seconds):
            ticks["n"] += 1
            if ticks["n"] >= 2:
                raise KeyboardInterrupt          # the loop's own stop path
        monkeypatch.setattr(m.time, "sleep", fake_sleep)

        with pytest.raises(SystemExit) as exc:
            self._run(monkeypatch, ["monitor", "--container", "c1", "--baseline", str(base),
                                    "--interval", "1"], collector)
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert "Monitoring" in out and "Stopping monitor" in out

    def test_invalid_verb_is_rejected(self, monkeypatch):
        import sys

        import escape_corpus.runtime_baseline as m
        monkeypatch.setattr(sys, "argv", ["runtime-baseline", "frobnicate", "--container", "c"])
        with pytest.raises(SystemExit) as exc:
            m.main()
        assert exc.value.code == 2
