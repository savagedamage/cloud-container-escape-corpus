"""False-positive (precision) tests: hardened pods must not be flagged scary.

BadPods only proves RECALL on maximally hostile manifests. Precision needs the
opposite input: pods that satisfy the Kubernetes Pod Security Standards
"restricted" profile — a documented, citable spec — must come out below HIGH. Any
check that fires on them is either (a) a legitimate finding beyond PSS (this tool
also scores resource limits, image pinning and service-account hygiene, which PSS
does not require), or (b) a false positive and a bug.

Each variant below is a different permutation of the restricted profile, because
the interesting failures are field-combination bugs (e.g. pod-level
securityContext inheritance), not single-field ones.
"""

import pytest

from escape_corpus.admission_review import AdmissionReviewer

APP_IMAGE = "registry.example.com/app@sha256:" + "a" * 64


def restricted_pod(**overrides):
    """A pod satisfying the Pod Security Standards 'restricted' profile."""
    spec = {
        "automountServiceAccountToken": False,
        "serviceAccountName": "app",
        "securityContext": {
            "runAsNonRoot": True,
            "runAsUser": 1000,
            "runAsGroup": 1000,
            "fsGroup": 1000,
            "seccompProfile": {"type": "RuntimeDefault"},
        },
        "containers": [{
            "name": "app",
            "image": APP_IMAGE,
            "securityContext": {
                "allowPrivilegeEscalation": False,
                "readOnlyRootFilesystem": True,
                "runAsNonRoot": True,
                "capabilities": {"drop": ["ALL"]},
                "seccompProfile": {"type": "RuntimeDefault"},
            },
            "resources": {"limits": {"cpu": "500m", "memory": "256Mi"},
                          "requests": {"cpu": "100m", "memory": "128Mi"}},
        }],
    }
    spec.update(overrides)
    return {"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "hardened", "namespace": "default"}, "spec": spec}


def review(pod):
    reviewer = AdmissionReviewer()
    reviewer.review_pod(pod)
    return reviewer.generate_report(pod, [])


def _pod_with(**container_over):
    """Restricted pod with a single container overridden."""
    container = dict(restricted_pod()["spec"]["containers"][0])
    container.update(container_over)
    return restricted_pod(containers=[container])


HARDENED_VARIANTS = [
    ("baseline restricted", restricted_pod()),
    ("container-level context only", restricted_pod(securityContext={
        "runAsNonRoot": True, "runAsUser": 1000,
        "seccompProfile": {"type": "RuntimeDefault"}})),
    ("no resources declared", _pod_with(**{"resources": {}})),
    ("tagged image", _pod_with(image="app:1.2.3")),
    ("NET_BIND_SERVICE only", _pod_with(securityContext={
        "allowPrivilegeEscalation": False, "runAsNonRoot": True,
        "capabilities": {"drop": ["ALL"], "add": ["NET_BIND_SERVICE"]},
        "readOnlyRootFilesystem": True})),
    ("emptyDir data volume", restricted_pod(
        volumes=[{"name": "data", "emptyDir": {}}],
        containers=[dict(restricted_pod()["spec"]["containers"][0],
                         volumeMounts=[{"name": "data", "mountPath": "/data"}])])),
    ("multi-container", restricted_pod(containers=[
        restricted_pod()["spec"]["containers"][0],
        dict(restricted_pod()["spec"]["containers"][0], name="sidecar"),
    ])),
    ("read-write rootfs", _pod_with(securityContext={
        "allowPrivilegeEscalation": False, "runAsNonRoot": True,
        "capabilities": {"drop": ["ALL"]}, "readOnlyRootFilesystem": False})),
]


@pytest.mark.parametrize("label,pod", HARDENED_VARIANTS, ids=[v[0] for v in HARDENED_VARIANTS])
def test_hardened_pods_are_not_flagged_high(label, pod):
    """A pod that complies with the restricted profile must not reach HIGH/CRITICAL.

    MEDIUM is acceptable and expected: this tool deliberately also scores things
    PSS does not require (resource limits, image pinning, SA hygiene).
    """
    report = review(pod)
    assert report.risk_level not in ("HIGH", "CRITICAL"), (
        f"{label}: {report.risk_level} ({report.risk_score}) "
        f"from {[f.check for f in report.findings]}")


def test_hardened_pod_findings_are_limited_to_documented_checks():
    """Pin down exactly which advisory checks fire on a compliant pod, so a future
    change that adds a scary check to a clean pod fails here rather than in the
    field."""
    report = review(restricted_pod())
    assert report.risk_level in ("LOW", "MEDIUM")
    # none of the escape-relevant checks may fire on a restricted pod
    escape_checks = {
        "privileged_container", "host_pid", "host_network", "host_ipc", "host_path_root",
        "host_path_proc", "docker_socket_mount", "containerd_socket_mount",
        "dangerous_capability", "capabilities_not_dropped", "allow_privilege_escalation",
        "no_seccomp_profile", "run_as_root", "no_run_as_non_root",
        "no_read_only_rootfs", "share_process_namespace", "host_path_etc",
    }
    fired = {f.check for f in report.findings}
    assert not (fired & escape_checks), f"false positive(s): {sorted(fired & escape_checks)}"


def test_a_single_hostile_field_still_flags(monkeypatch):
    """Precision work must not blunt detection: one dangerous field on an otherwise
    restricted pod still has to trip the tool."""
    pod = restricted_pod(hostPID=True)
    assert review(pod).risk_level in ("HIGH", "CRITICAL")
