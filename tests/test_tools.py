#!/usr/bin/env python3
"""Unit tests for drift detector + admission reviewer without needing a cluster."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from escape_corpus.admission_review import AdmissionReviewer, load_pod_spec
from escape_corpus.runtime_baseline import (
    CapabilitySnapshot,
    CgroupSnapshot,
    DriftDetector,
    MountSnapshot,
    NamespaceSnapshot,
    ProcSnapshot,
    RuntimeSnapshot,
)


def make_snapshot(**overrides):
    base = dict(
        timestamp="2026-09-16T00:00:00+00:00",
        container_id="test",
        capabilities=CapabilitySnapshot(
            cap_eff="00000000a80425fb", cap_prm="00000000a80425fb",
            cap_inh="0000000000000000", cap_bnd="00000000a80425fb",
            cap_amb="0000000000000000", securebits="0000000000000000",
            seccomp_mode="2", no_new_privs=True,
        ),
        cgroups=CgroupSnapshot(
            cgroup_path="0::/docker/abc123", cgroup_version="v2",
            controllers=["cpu", "memory", "pids"], cpu_limit="100000 100000",
            memory_limit="1073741824", pids_limit="64", cgroup_procs_count=1,
        ),
        namespaces=NamespaceSnapshot(
            pid_ns="pid:[4026531836]", mnt_ns="mnt:[4026531841]",
            net_ns="net:[4026531840]", uts_ns="uts:[4026531838]",
            ipc_ns="ipc:[4026531839]", user_ns="user:[4026531837]",
            cgroup_ns="cgroup:[4026531835]", time_ns="time:[4026531834]",
        ),
        proc=ProcSnapshot(
            pid=1, ppid=0, uid=0, gid=0, cmdline="/bin/sh",
            exe_link="/usr/bin/sleep", root_link="/",
            mounted_procs=[], mounted_sys=True, host_pid_visible=False,
        ),
        mounts=MountSnapshot(
            docker_sock=False, containerd_sock=False, cri_o_sock=False,
            host_root=False, host_proc=False, host_sys=False,
            sensitive_mounts=[], read_only_rootfs=True,
        ),
        hash_chain="0" * 64, previous_hash=None,
    )
    base.update(overrides)
    return RuntimeSnapshot(**base)


def test_clean_state_no_drift():
    baseline = make_snapshot()
    current = make_snapshot(previous_hash=baseline.hash_chain)
    findings = DriftDetector(baseline).detect(current)
    assert findings == [], f"Expected no findings, got {findings}"
    print("PASS: clean state -> no drift")


def test_namespace_escape_detected():
    baseline = make_snapshot()
    ns = baseline.namespaces
    escaped_ns = NamespaceSnapshot(
        pid_ns="pid:[1]", mnt_ns="mnt:[1]", net_ns="net:[1]",
        uts_ns=ns.uts_ns, ipc_ns=ns.ipc_ns, user_ns=ns.user_ns,
        cgroup_ns=ns.cgroup_ns, time_ns=ns.time_ns,
    )
    current = make_snapshot(namespaces=escaped_ns, previous_hash=baseline.hash_chain)
    findings = DriftDetector(baseline).detect(current)
    cats = {f["category"]: f for f in findings}
    assert "namespace" in cats, f"Expected namespace finding, got {findings}"
    assert cats["namespace"]["level"] == "CRITICAL"
    print(f"PASS: namespace escape -> {len(findings)} findings incl CRITICAL namespace")


def test_docker_sock_mount_detected():
    baseline = make_snapshot()
    bad = MountSnapshot(
        docker_sock=True, containerd_sock=False, cri_o_sock=False,
        host_root=False, host_proc=False, host_sys=False,
        sensitive_mounts=["docker.sock"], read_only_rootfs=True,
    )
    current = make_snapshot(mounts=bad, previous_hash=baseline.hash_chain)
    findings = DriftDetector(baseline).detect(current)
    assert any(f["category"] == "mount" and "Docker socket" in f["description"] for f in findings)
    print("PASS: docker.sock mount drift detected")


def test_hash_chain_break_detected():
    baseline = make_snapshot()
    current = make_snapshot(previous_hash="f" * 64)  # wrong previous hash
    findings = DriftDetector(baseline).detect(current)
    assert any(f["category"] == "integrity" for f in findings)
    print("PASS: hash chain break detected")


def test_admission_escape_pod():
    pod = load_pod_spec(str(Path(__file__).parent / "escape-test-pod.yaml"))
    reviewer = AdmissionReviewer()
    reviewer.review_pod(pod)
    report = reviewer.generate_report(pod, [])
    sevs = [f.severity for f in report.findings]
    assert report.risk_level == "CRITICAL", f"Expected CRITICAL, got {report.risk_level}"
    assert "CRITICAL" in sevs, "Expected CRITICAL findings"
    assert any(f.check == "privileged_container" for f in report.findings)
    assert any(f.check == "docker_socket_mount" for f in report.findings)
    assert any(f.check == "dangerous_capabilities" for f in report.findings)
    assert any(f.check == "env_secret_hardcoded" for f in report.findings)
    print(f"PASS: escape pod -> CRITICAL, {len(report.findings)} findings, score={report.risk_score}")


def test_admission_secure_pod():
    pod = load_pod_spec(str(Path(__file__).parent / "secure-test-pod.yaml"))
    reviewer = AdmissionReviewer()
    reviewer.review_pod(pod)
    report = reviewer.generate_report(pod, [])
    critical = [f for f in report.findings if f.severity in ("CRITICAL", "HIGH")]
    assert not critical, f"Expected no CRITICAL/HIGH, got {critical}"
    print(f"PASS: secure pod -> {report.risk_level}, {len(report.findings)} findings, no CRITICAL/HIGH")


if __name__ == "__main__":
    test_clean_state_no_drift()
    test_namespace_escape_detected()
    test_docker_sock_mount_detected()
    test_hash_chain_break_detected()
    test_admission_escape_pod()
    test_admission_secure_pod()
    print("\nALL TESTS PASSED")
