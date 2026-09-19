"""Tests for the admission_review policy engine and the full builtin check matrix.

`review_pod` has 24+ builtin checks; this file drives the ones not already
covered by tests/test_tools.py so a regression in any single check is caught.
"""

import io
import json
import sys

import pytest
import yaml

from escape_corpus.admission_review import (
    SEVERITY_WEIGHTS,
    AdmissionReviewer,
    load_pod_spec,
    load_policies,
)


def pod(**spec_over):
    base = {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "t", "namespace": "default"},
        "spec": {"containers": [{"name": "c", "image": "nginx:1.25"}]},
    }
    base["spec"].update(spec_over)
    return base


def checks(p, policies=None):
    r = AdmissionReviewer()
    r.review_pod(p)
    findings = r.findings + (r.review_against_policies(p, policies) if policies else [])
    return {f.check for f in findings}, {f.check for f in r.findings}, set(r.passed_checks)


class TestBuiltinCheckMatrix:
    def test_ephemeral_containers_and_aliases(self):
        found, _, _ = checks(pod(ephemeralContainers=[{"name": "dbg", "image": "busybox"}],
                                 hostAliases=[{"ip": "1.2.3.4", "hostnames": ["x"]}]))
        assert {"ephemeral_container_use", "host_aliases_use"} <= found

    def test_control_plane_node_selector(self):
        found, _, _ = checks(pod(nodeSelector={"node-role.kubernetes.io/control-plane": ""}))
        assert "node_selector_control_plane" in found

    def test_share_process_namespace(self):
        found, _, _ = checks(pod(shareProcessNamespace=True))
        assert "share_process_namespace" in found

    def test_service_account_and_token_automount(self):
        found, _, _ = checks(pod(serviceAccountName="default", automountServiceAccountToken=True))
        assert {"service_account_default", "automount_service_account_token"} <= found

    def test_csi_volume_reviewed(self):
        found, _, _ = checks(pod(volumes=[{"name": "v", "csi": {"driver": "my.driver.io"}}]))
        assert "host_path_mount" in found

    def test_dind_image_and_cgroup_mount(self):
        p = pod(containers=[{
            "name": "dind", "image": "docker:dind",
            "volumeMounts": [{"name": "cg", "mountPath": "/sys/fs/cgroup"}],
        }], volumes=[{"name": "cg", "hostPath": {"path": "/sys/fs/cgroup"}}])
        found, _, _ = checks(p)
        assert {"docker_in_docker", "cgroup_volume_mount"} <= found

    def test_sys_admin_with_proc_mount_combo(self):
        """The combination is what enables the cgroup escape, so it is scored
        separately from either half alone."""
        p = pod(containers=[{
            "name": "c", "image": "ubuntu",
            "securityContext": {"capabilities": {"add": ["SYS_ADMIN"]}},
            "volumeMounts": [{"name": "p", "mountPath": "/proc"}],
        }], volumes=[{"name": "p", "hostPath": {"path": "/proc"}}])
        found, _, _ = checks(p)
        assert "sys_admin_with_proc_mount" in found
        assert "proc_mount" in found
        assert "dangerous_capabilities" in found

    def test_subpath_mount_flagged(self):
        p = pod(containers=[{
            "name": "c", "image": "ubuntu",
            "volumeMounts": [{"name": "v", "mountPath": "/data", "subPath": "x"}],
        }], volumes=[{"name": "v", "emptyDir": {}}])
        found, _, _ = checks(p)
        assert "sub_path_mount" in found

    def test_empty_dir_disk_backed_for_secretish_volume(self):
        p = pod(containers=[{"name": "c", "image": "ubuntu",
                             "volumeMounts": [{"name": "secret-tmp", "mountPath": "/s"}]}],
                volumes=[{"name": "secret-tmp", "emptyDir": {}}])
        found, _, _ = checks(p)
        assert "empty_dir_medium" in found

    def test_env_from_secretref_all_keys(self):
        p = pod(containers=[{"name": "c", "image": "ubuntu",
                             "envFrom": [{"secretRef": {"name": "s"}}]}])
        found, _, _ = checks(p)
        assert "env_from_secret_all_keys" in found

    def test_hardcoded_secret_in_env(self):
        p = pod(containers=[{"name": "c", "image": "ubuntu",
                             "env": [{"name": "DB_PASSWORD", "value": "hunter2"}]}])
        found, _, _ = checks(p)
        assert "env_secret_hardcoded" in found

    def test_no_security_context_anywhere(self):
        found, _, _ = checks(pod())
        assert "no_security_context" in found

    def test_hostpath_sensitive_targets(self):
        for path, expected in [("/var/run/docker.sock", "docker_socket_mount"),
                               ("/etc", "host_path_etc"),
                               ("/etc/kubernetes", "host_path_kube"),
                               ("/.kube", "host_path_kube")]:
            p = pod(containers=[{"name": "c", "image": "ubuntu",
                                 "volumeMounts": [{"name": "v", "mountPath": path}]}],
                    volumes=[{"name": "v", "hostPath": {"path": path}}])
            found, _, _ = checks(p)
            assert expected in found, f"{path} -> {found}"

    def test_secure_pod_reports_passes_not_findings(self):
        p = pod(securityContext={"runAsNonRoot": True, "runAsUser": 1000,
                                 "seccompProfile": {"type": "RuntimeDefault"}},
                containers=[{"name": "c", "image": "nginx@sha256:" + "a" * 64,
                             "securityContext": {"allowPrivilegeEscalation": False,
                                                 "readOnlyRootFilesystem": True,
                                                 "capabilities": {"drop": ["ALL"]}},
                             "resources": {"limits": {"cpu": "1", "memory": "1Gi"}}}])
        found, builtin, passed = checks(p)
        assert not {"privileged_container", "allow_privilege_escalation",
                    "capabilities_not_dropped", "no_read_only_rootfs",
                    "no_seccomp_profile", "image_latest_tag"} & found
        assert {"no_read_only_rootfs", "allow_privilege_escalation",
                "no_seccomp_profile"} <= passed

    def test_latest_tag_flagged(self):
        found, _, _ = checks(pod(containers=[{"name": "c", "image": "ubuntu:latest"}]))
        assert "image_latest_tag" in found


class TestPolicyEngine:
    def test_required_kind(self):
        p = pod(containers=[{"name": "c", "image": "u", "securityContext": {}}])
        found, _, _ = checks(p, {"need-nonroot": {
            "kind": "required", "path": "spec.containers[*].securityContext.runAsNonRoot",
            "severity": "HIGH", "message": "must set runAsNonRoot"}})
        assert "need-nonroot" in found

    def test_forbidden_kind(self):
        p = pod(hostNetwork=True)
        found, _, _ = checks(p, {"no-host-net": {
            "kind": "forbidden", "path": "spec.hostNetwork", "severity": "CRITICAL"}})
        assert "no-host-net" in found

    def test_equals_kind(self):
        p = pod(containers=[{"name": "c", "image": "u",
                             "securityContext": {"capabilities": {"drop": ["NET_RAW"]}}}])
        found, _, _ = checks(p, {"drop-all": {
            "kind": "equals", "path": "spec.containers[*].securityContext.capabilities.drop",
            "value": ["ALL"], "severity": "HIGH"}})
        assert "drop-all" in found

    def test_not_in_kind(self):
        p = pod(containers=[{"name": "c", "image": "ubuntu:latest"}])
        found, _, _ = checks(p, {"allowed-images": {
            "kind": "not_in", "path": "spec.containers[*].image",
            "values": ["ubuntu:latest"], "severity": "MEDIUM"}})
        assert "allowed-images" in found

    def test_disabled_policy_is_skipped(self):
        p = pod(containers=[{"name": "c", "image": "ubuntu:latest"}])
        found, _, _ = checks(p, {"off": {
            "kind": "not_in", "path": "spec.containers[*].image",
            "values": ["ubuntu:latest"], "disabled": True}})
        assert "off" not in found

    def test_policy_findings_carry_source_and_remediation(self):
        p = pod(hostNetwork=True)          # must actually violate the policy
        r = AdmissionReviewer()
        r.review_pod(p)
        found = r.review_against_policies(p, {"x": {
            "kind": "forbidden", "path": "spec.hostNetwork", "severity": "LOW",
            "message": "m", "remediation": "r", "source": "kyverno"}})
        assert found and found[0].policy_source == "kyverno"
        assert found[0].remediation == "r"

    def test_path_navigation_with_index_and_missing_keys(self):
        r = AdmissionReviewer()
        p = pod(containers=[{"name": "a", "image": "i0"}, {"name": "b", "image": "i1"}])
        assert r._get_path_value(p, "spec.containers[0].image") == "i0"
        assert r._get_path_value(p, "spec.containers[1].image") == "i1"
        assert r._get_path_value(p, "spec.containers[*].image") == "i0"
        assert r._get_path_value(p, "spec.does.not.exist") is None
        assert r._get_path_value(p, "spec.containers[9].image") is None
        assert r._get_path_value(p, "") is None

    def test_empty_policy_set_is_allowed(self):
        r = AdmissionReviewer()
        p = pod()
        r.review_pod(p)
        assert r.review_against_policies(p, {}) == []


class TestSeverityScoring:
    def test_report_score_is_weight_sum(self):
        r = AdmissionReviewer()
        p = pod(hostNetwork=True, hostPID=True)
        r.review_pod(p)
        report = r.generate_report(p, [])
        assert report.risk_score == sum(SEVERITY_WEIGHTS[f.severity] for f in report.findings)
        assert report.total_findings == len(report.findings)

    def test_policy_violations_are_separated_from_builtin(self):
        r = AdmissionReviewer()
        p = pod(hostNetwork=True)
        r.review_pod(p)
        violations = r.review_against_policies(p, {"no-net": {
            "kind": "forbidden", "path": "spec.hostNetwork", "severity": "HIGH"}})
        report = r.generate_report(p, violations)
        assert report.policy_violations == violations
        # the reviewer's own list stays builtin-only; policy findings are merged
        # into the report and also kept separately for gate-consumers
        assert all(f.policy_source == "builtin" for f in r.findings)
        assert all(v in report.findings for v in violations)


class TestSpecLoading:
    def test_yaml_and_json_equivalent(self, tmp_path):
        spec = pod(hostNetwork=True)
        y = tmp_path / "p.yaml"
        j = tmp_path / "p.json"
        y.write_text(yaml.safe_dump(spec))
        j.write_text(json.dumps(spec))
        assert load_pod_spec(str(y)) == load_pod_spec(str(j))

    def test_stdin_spec(self, monkeypatch):
        monkeypatch.setattr(sys, "stdin", io.StringIO(yaml.safe_dump(pod(hostPID=True))))
        assert load_pod_spec("-")["spec"]["hostPID"] is True

    def test_unparseable_spec_raises(self, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text("just: [a, scalar\n")
        with pytest.raises(ValueError, match="Failed to parse"):
            load_pod_spec(str(bad))

    def test_policies_loader_handles_yaml_and_json(self, tmp_path):
        p = {"x": {"kind": "required", "path": "spec.hostNetwork"}}
        y = tmp_path / "pol.yaml"
        j = tmp_path / "pol.json"
        y.write_text(yaml.safe_dump(p))
        j.write_text(json.dumps(p))
        assert load_policies(str(y)) == load_policies(str(j))

    def test_missing_policy_file_raises(self):
        with pytest.raises(FileNotFoundError):
            load_policies("/nonexistent/policies.yaml")
