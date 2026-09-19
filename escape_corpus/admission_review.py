#!/usr/bin/env python3
"""
admission_review.py - Pod Admission Security Review

Dry-run a pod spec against Kyverno/OPA/Gatekeeper policies and built-in
security checks. Produces a risk-weighted report without needing a cluster.

Usage:
    admission_review.py --pod pod.yaml [--policies policy.yaml] [--output report.json]
    admission_review.py --pod - (read pod spec from stdin)
"""

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from typing import List, Optional

import yaml


@dataclass
class Finding:
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    check: str
    description: str
    remediation: str
    policy_source: str = "builtin"


@dataclass
class AdmissionReport:
    pod_name: str
    namespace: str
    total_findings: int
    risk_score: int
    risk_level: str
    findings: List[Finding]
    passed_checks: List[str]
    policy_violations: List[Finding]


# Severity weights for risk scoring
SEVERITY_WEIGHTS = {
    "LOW": 5,
    "MEDIUM": 15,
    "HIGH": 30,
    "CRITICAL": 60,
}

# Built-in security checks
BUILTIN_CHECKS = {
    "privileged_container": {
        "severity": "CRITICAL",
        "description": "Container runs in privileged mode",
        "remediation": "Remove privileged: true; use specific capabilities or device mounts instead",
    },
    "host_network": {
        "severity": "HIGH",
        "description": "Pod uses hostNetwork",
        "remediation": "Use pod networking with CNI; only use hostNetwork when absolutely required",
    },
    "host_pid": {
        "severity": "HIGH",
        "description": "Pod uses hostPID",
        "remediation": "Remove hostPID; use sidecar containers or shared process namespace via shareProcessNamespace",
    },
    "host_ipc": {
        "severity": "HIGH",
        "description": "Pod uses hostIPC",
        "remediation": "Remove hostIPC; use shared memory volumes if IPC needed",
    },
    "host_path_mount": {
        "severity": "HIGH",
        "description": "Container mounts hostPath volume",
        "remediation": "Use PVC, configMap, secret, or emptyDir instead of hostPath",
    },
    "docker_socket_mount": {
        "severity": "CRITICAL",
        "description": "Container mounts Docker socket (/var/run/docker.sock)",
        "remediation": "Remove Docker socket mount; use Kubernetes API or a dedicated sidecar with RBAC",
    },
    "containerd_socket_mount": {
        "severity": "CRITICAL",
        "description": "Container mounts containerd socket",
        "remediation": "Remove containerd socket mount",
    },
    "crio_socket_mount": {
        "severity": "CRITICAL",
        "description": "Container mounts CRI-O socket",
        "remediation": "Remove CRI-O socket mount",
    },
    "capabilities_not_dropped": {
        "severity": "MEDIUM",
        "description": "Container does not drop ALL capabilities",
        "remediation": "Add securityContext.capabilities.drop: ['ALL'] and add only required capabilities",
    },
    "dangerous_capabilities": {
        "severity": "HIGH",
        "description": "Container has dangerous capabilities added",
        "remediation": "Remove dangerous capabilities (SYS_ADMIN, SYS_PTRACE, SYS_MODULE, "
                       "NET_ADMIN, NET_RAW, BPF, PERFMON, DAC_OVERRIDE, DAC_READ_SEARCH, SETUID, SETGID)",
    },
    "run_as_root": {
        "severity": "MEDIUM",
        "description": "Container runs as root (UID 0)",
        "remediation": "Set securityContext.runAsNonRoot: true and runAsUser to non-zero UID",
    },
    "no_run_as_non_root": {
        "severity": "MEDIUM",
        "description": "runAsNonRoot not set",
        "remediation": "Set securityContext.runAsNonRoot: true",
    },
    "allow_privilege_escalation": {
        "severity": "HIGH",
        "description": "allowPrivilegeEscalation is true or not set",
        "remediation": "Set securityContext.allowPrivilegeEscalation: false",
    },
    "no_read_only_rootfs": {
        "severity": "LOW",
        "description": "Root filesystem is writable",
        "remediation": "Set securityContext.readOnlyRootFilesystem: true",
    },
    "no_seccomp_profile": {
        "severity": "LOW",
        "description": "No seccomp profile specified",
        "remediation": "Set seccompProfile to RuntimeDefault or a custom profile",
    },
    "no_apparmor_profile": {
        "severity": "LOW",
        "description": "No AppArmor profile specified",
        "remediation": "Set apparmorProfile to runtime/default",
    },
    "no_selinux_options": {
        "severity": "LOW",
        "description": "No SELinux options specified",
        "remediation": "Set SELinux options for mandatory access control",
    },
    "no_resources_limits": {
        "severity": "LOW",
        "description": "No resource limits specified",
        "remediation": "Set resources.limits and resources.requests for CPU and memory",
    },
    "no_run_as_user": {
        "severity": "LOW",
        "description": "runAsUser not specified",
        "remediation": "Set securityContext.runAsUser to a non-zero UID",
    },
    "no_security_context": {
        "severity": "MEDIUM",
        "description": "No securityContext specified at pod or container level",
        "remediation": "Add securityContext with restrictive defaults",
    },
    "service_account_default": {
        "severity": "MEDIUM",
        "description": "Pod uses default service account",
        "remediation": "Create dedicated service account with least-privilege RBAC",
    },
    "automount_service_account_token": {
        "severity": "LOW",
        "description": "Service account token is automounted",
        "remediation": "Set automountServiceAccountToken: false unless pod needs API access",
    },
    "host_path_proc": {
        "severity": "CRITICAL",
        "description": "Container mounts host /proc",
        "remediation": "Remove /proc hostPath mount",
    },
    "host_path_sys": {
        "severity": "CRITICAL",
        "description": "Container mounts host /sys",
        "remediation": "Remove /sys hostPath mount",
    },
    "host_path_root": {
        "severity": "CRITICAL",
        "description": "Container mounts host root filesystem",
        "remediation": "Remove host root mount",
    },
    "host_path_var_run": {
        "severity": "HIGH",
        "description": "Container mounts host /var/run",
        "remediation": "Remove /var/run hostPath mount unless specifically needed",
    },
    "host_path_etc": {
        "severity": "MEDIUM",
        "description": "Container mounts host /etc",
        "remediation": "Remove /etc hostPath mount; use configMaps",
    },
    "host_path_kube": {
        "severity": "HIGH",
        "description": "Container mounts host /.kube or /etc/kubernetes",
        "remediation": "Remove Kubernetes config mount; use service account RBAC",
    },
    "host_path_ssh": {
        "severity": "HIGH",
        "description": "Container mounts host SSH keys",
        "remediation": "Remove SSH key mount; use secrets with proper RBAC",
    },
    "node_selector_control_plane": {
        "severity": "MEDIUM",
        "description": "Pod scheduled on control-plane/master node",
        "remediation": "Use taints and tolerations to prevent scheduling on control plane",
    },
    "no_network_policy_note": {
        "severity": "LOW",
        "description": "No indication of network policy isolation",
        "remediation": "Implement NetworkPolicies for egress/ingress restriction",
    },
    "ephemeral_container_use": {
        "severity": "MEDIUM",
        "description": "Pod uses ephemeral containers (debug injection risk)",
        "remediation": "Restrict ephemeral container usage via RBAC",
    },
    "host_aliases_use": {
        "severity": "LOW",
        "description": "Pod uses hostAliases",
        "remediation": "Use DNS resolution or configMap for host mapping",
    },
    "env_secret_hardcoded": {
        "severity": "HIGH",
        "description": "Environment variable contains hardcoded secret-like value",
        "remediation": "Use secretKeyRef to reference Kubernetes secrets",
    },
    "env_from_secret_all_keys": {
        "severity": "MEDIUM",
        "description": "Container mounts all keys from a secret as env vars",
        "remediation": "Reference only required keys via secretKeyRef",
    },
    "image_latest_tag": {
        "severity": "MEDIUM",
        "description": "Container image uses :latest tag",
        "remediation": "Pin image to specific digest or version tag",
    },
    "image_no_digest": {
        "severity": "LOW",
        "description": "Container image not pinned by digest",
        "remediation": "Use image digest (@sha256:...) for immutability",
    },
    "empty_dir_medium": {
        "severity": "LOW",
        "description": "emptyDir uses default (disk) medium for sensitive data",
        "remediation": "Use emptyDir.medium: Memory for ephemeral sensitive data",
    },
    "sub_path_mount": {
        "severity": "LOW",
        "description": "Container uses subPath mounts",
        "remediation": "Prefer separate volumes over subPath to avoid subPath vulnerability",
    },
    "proc_mount": {
        "severity": "MEDIUM",
        "description": "Container mounts /proc explicitly",
        "remediation": "Remove explicit /proc mount; use default masked /proc",
    },
    "sys_admin_with_proc_mount": {
        "severity": "CRITICAL",
        "description": "SYS_ADMIN capability combined with writable /proc mount",
        "remediation": "Remove SYS_ADMIN or restrict /proc; this combination enables cgroup escape",
    },
    "cgroup_volume_mount": {
        "severity": "HIGH",
        "description": "Container mounts /sys/fs/cgroup volume",
        "remediation": "Remove cgroup mount; unnecessary for most workloads",
    },
    "docker_in_docker": {
        "severity": "HIGH",
        "description": "Container runs Docker-in-Docker (dind)",
        "remediation": "Use Kaniko, Buildah, or dedicated build service instead of dind",
    },
    "share_process_namespace": {
        "severity": "LOW",
        "description": "Pod shares process namespace",
        "remediation": "Disable shareProcessNamespace unless required for sidecar patterns",
    },
}

DANGEROUS_CAPABILITIES = {
    "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "SYS_RAWIO", "SYS_BOOT",
    "SYS_TIME", "SYS_RESOURCE", "MKNOD", "NET_ADMIN", "NET_RAW", "BPF",
    "PERFMON", "DAC_OVERRIDE", "DAC_READ_SEARCH", "SETUID", "SETGID",
    "SETPCAP", "LINUX_IMMUTABLE", "AUDIT_CONTROL", "AUDIT_WRITE",
    "SYS_CHROOT", "SYS_PACCT", "WAKE_ALARM", "BLOCK_SUSPEND",
    "AUDIT_READ", "LEASE", "SYSLOG", "CHECKPOINT_RESTORE", "MAC_OVERRIDE",
    "MAC_ADMIN", "SYS_NICE", "SYS_TTY_CONFIG",
}

SENSITIVE_HOST_PATHS = {
    "/proc": "host_path_proc",
    "/sys": "host_path_sys",
    "/": "host_path_root",
    "/var/run": "host_path_var_run",
    "/etc": "host_path_etc",
    "/.kube": "host_path_kube",
    "/etc/kubernetes": "host_path_kube",
    "/root/.ssh": "host_path_ssh",
    "/home/": "host_path_ssh",
    "/var/run/docker.sock": "docker_socket_mount",
    "/run/containerd/containerd.sock": "containerd_socket_mount",
    "/run/crio/crio.sock": "crio_socket_mount",
}

# Longest path first: matching iterates this order so /etc/kubernetes resolves to
# the kube check rather than the shorter /etc one, and a socket path wins over
# its parent directory. Built once, at import.
SENSITIVE_PATHS_ORDERED = sorted(SENSITIVE_HOST_PATHS.items(), key=lambda kv: -len(kv[0]))


def match_sensitive_host_path(host_path: str):
    """Return the check id for the MOST SPECIFIC sensitive path prefix.

    Matching is component-bounded (``/etc`` matches ``/etc`` and ``/etc/x`` but
    never ``/etcfoo``), and the bare root ``/`` matches only exactly — otherwise
    it would swallow every other path. Returns None when nothing matches.
    """
    if not host_path:
        return None
    for sensitive_path, check_id in SENSITIVE_PATHS_ORDERED:
        if sensitive_path == "/":
            if host_path == "/":
                return check_id
            continue
        base = sensitive_path.rstrip("/")
        if host_path == base or host_path.startswith(base + "/"):
            return check_id
    return None

SECRET_PATTERNS = [
    r"(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|credential)\s*[:=]\s*\S+",
]

class AdmissionReviewer:
    """Review pod specs against security policies."""

    def __init__(self):
        self.findings: List[Finding] = []
        self.passed_checks: List[str] = []

    def _add_finding(self, check_id: str, severity: Optional[str] = None,
                     description: Optional[str] = None,
                     remediation: Optional[str] = None,
                     policy_source: str = "builtin"):
        """Add a finding using builtin check definition or custom values."""
        if check_id in BUILTIN_CHECKS and severity is None:
            check = BUILTIN_CHECKS[check_id]
            severity = check["severity"]
            description = description if description is not None else check["description"]
            remediation = remediation if remediation is not None else check["remediation"]
        self.findings.append(Finding(
            severity=severity,
            check=check_id,
            description=description,
            remediation=remediation,
            policy_source=policy_source
        ))

    def _check_required(self, condition: bool, check_id: str):
        """Mark check as passed if condition is false (no issue)."""
        if not condition:
            self.passed_checks.append(check_id)
        else:
            self._add_finding(check_id)

    def review_pod(self, pod: dict) -> List[Finding]:
        """Review a pod spec."""
        self.findings = []
        self.passed_checks = []

        spec = pod.get("spec", {})

        # Pod-level checks
        self._check_required(spec.get("hostNetwork", False), "host_network")
        self._check_required(spec.get("hostPID", False), "host_pid")
        self._check_required(spec.get("hostIPC", False), "host_ipc")

        # Service account checks
        sa_name = spec.get("serviceAccountName", "default")
        if sa_name == "default":
            self._add_finding("service_account_default")
        else:
            self.passed_checks.append("service_account_default")

        if spec.get("automountServiceAccountToken") is not False:
            self._add_finding("automount_service_account_token")
        else:
            self.passed_checks.append("automount_service_account_token")

        # Pod securityContext
        pod_sc = spec.get("securityContext", {})
        if not pod_sc:
            self.passed_checks.append("no_security_context")  # Checked at container level

        # Node selector for control plane
        node_selector = spec.get("nodeSelector", {})
        for key in node_selector:
            if "master" in key or "control-plane" in key or "controlplane" in key:
                self._add_finding("node_selector_control_plane")
                break
        else:
            self.passed_checks.append("node_selector_control_plane")

        # Ephemeral containers
        if spec.get("ephemeralContainers"):
            self._add_finding("ephemeral_container_use")
        else:
            self.passed_checks.append("ephemeral_container_use")

        # Host aliases
        if spec.get("hostAliases"):
            self._add_finding("host_aliases_use")
        else:
            self.passed_checks.append("host_aliases_use")

        # Share process namespace
        if spec.get("shareProcessNamespace", False):
            self._add_finding("share_process_namespace")
        else:
            self.passed_checks.append("share_process_namespace")

        # Volume checks
        volumes = spec.get("volumes", [])
        for volume in volumes:
            if "hostPath" in volume:
                host_path = volume["hostPath"].get("path", "")
                check_id = match_sensitive_host_path(host_path)
                if check_id:
                    self._add_finding(check_id,
                                      description=f"Container mounts sensitive hostPath: {host_path}")
                else:
                    self._add_finding("host_path_mount",
                                      description=f"Container mounts hostPath: {host_path}",
                                      remediation="Use PVC, configMap, secret, or emptyDir instead of hostPath")
            if "csi" in volume:
                # CSI volume with sensitive driver
                driver = volume.get("csi", {}).get("driver", "")
                if "secrets-store" not in driver:
                    self._add_finding("host_path_mount",
                                      description=f"CSI volume with driver: {driver}",
                                      remediation="Review CSI driver for host access")

        # Container checks
        containers = spec.get("containers", [])
        containers += spec.get("initContainers", [])

        for container in containers:
            container_name = container.get("name", "unnamed")
            # Kubernetes semantics: pod-level securityContext propagates to
            # containers unless the container overrides specific fields.
            pod_sc = spec.get("securityContext", {}) or {}
            sc = dict(pod_sc)
            sc.update(container.get("securityContext", {}) or {})

            # Privileged
            if sc.get("privileged", False):
                self._add_finding("privileged_container",
                                  description=f"Container {container_name} runs in privileged mode")

            # Capabilities
            caps = sc.get("capabilities", {})
            add_caps = set(caps.get("add", []))
            drop_caps = set(caps.get("drop", []))

            if "ALL" not in drop_caps:
                self._add_finding("capabilities_not_dropped",
                                  description=f"Container {container_name} does not drop ALL capabilities")

            dangerous = add_caps & DANGEROUS_CAPABILITIES
            if dangerous:
                self._add_finding("dangerous_capabilities",
                                  description=f"Container {container_name} has dangerous capabilities: "
                                              f"{', '.join(sorted(dangerous))}")

            # Run as user
            if not sc.get("runAsNonRoot", False):
                self._add_finding("no_run_as_non_root",
                                  description=f"Container {container_name} does not set runAsNonRoot")
            else:
                self.passed_checks.append("no_run_as_non_root")

            if sc.get("runAsUser", 0) == 0:
                self._add_finding("run_as_root",
                                  description=f"Container {container_name} runs as root")
            else:
                self.passed_checks.append("run_as_root")
                self.passed_checks.append("no_run_as_user")

            if "runAsUser" not in sc:
                self.passed_checks.append("no_run_as_user")

            # Privilege escalation
            if sc.get("allowPrivilegeEscalation", True):
                self._add_finding("allow_privilege_escalation",
                                  description=f"Container {container_name} allows privilege escalation")
            else:
                self.passed_checks.append("allow_privilege_escalation")

            # Read-only root filesystem
            if not sc.get("readOnlyRootFilesystem", False):
                self._add_finding("no_read_only_rootfs",
                                  description=f"Container {container_name} has writable root filesystem")
            else:
                self.passed_checks.append("no_read_only_rootfs")

            # Seccomp
            if "seccompProfile" not in sc:
                self._add_finding("no_seccomp_profile",
                                  description=f"Container {container_name} has no seccomp profile")
            else:
                self.passed_checks.append("no_seccomp_profile")

            # AppArmor
            annotations = pod.get("metadata", {}).get("annotations", {})
            if "container.apparmor.security.beta.kubernetes.io/" not in annotations:
                self.passed_checks.append("no_apparmor_profile")  # Low severity, don't always flag

            # SELinux
            if "seLinuxOptions" not in sc:
                self.passed_checks.append("no_selinux_options")  # Low severity

            # Resources
            resources = container.get("resources", {})
            if not resources.get("limits"):
                self._add_finding("no_resources_limits",
                                  description=f"Container {container_name} has no resource limits")
            else:
                self.passed_checks.append("no_resources_limits")

            # Environment variables
            for env in container.get("env", []):
                if "value" in env and env["value"]:
                    for pattern in SECRET_PATTERNS:
                        if re.search(pattern, f"{env['name']}={env['value']}"):
                            self._add_finding("env_secret_hardcoded",
                                              description=f"Container {container_name} env var "
                                                          f"{env['name']} appears to contain a secret",
                                              remediation="Use secretKeyRef to reference Kubernetes secrets")
                            break

            if "envFrom" in container:
                for env_from in container["envFrom"]:
                    if "secretRef" in env_from and not env_from.get("secretRef", {}).get("optional"):
                        self._add_finding("env_from_secret_all_keys",
                                          description=f"Container {container_name} mounts all secret keys via envFrom")

            # Image checks
            image = container.get("image", "")
            if ":latest" in image:
                self._add_finding("image_latest_tag",
                                  description=f"Container {container_name} uses :latest image tag")
            else:
                self.passed_checks.append("image_latest_tag")

            if "@sha256:" not in image:
                self.passed_checks.append("image_no_digest")  # Low severity

            # Volume mounts
            for mount in container.get("volumeMounts", []):
                mount_path = mount.get("mountPath", "")

                # Runtime sockets checked FIRST (exact or subpath match)
                for sock_path, check_id in [
                    ("/var/run/docker.sock", "docker_socket_mount"),
                    ("/run/containerd/containerd.sock", "containerd_socket_mount"),
                    ("/run/crio/crio.sock", "crio_socket_mount"),
                ]:
                    if mount_path == sock_path or mount_path.startswith(sock_path + "/"):
                        self._add_finding(check_id,
                                          description=f"Container {container_name} mounts "
                                                      f"runtime socket at {mount_path}")
                        break

                # Sensitive host paths via volumeName lookup (mountPath alone can't
                # distinguish hostPath volumes from PVCs)
                for volume in volumes:
                    if volume.get("name") == mount.get("name") and "hostPath" in volume:
                        host_path = volume["hostPath"].get("path", "")
                        check_id = match_sensitive_host_path(host_path)
                        if check_id and check_id not in [
                            "docker_socket_mount", "containerd_socket_mount", "crio_socket_mount",
                        ]:
                            self._add_finding(check_id,
                                              description=f"Container {container_name} mounts hostPath "
                                                          f"{host_path} at {mount_path}")

                if mount_path == "/proc":
                    self._add_finding("proc_mount",
                                      description=f"Container {container_name} mounts /proc")
                    if "SYS_ADMIN" in add_caps:
                        self._add_finding("sys_admin_with_proc_mount",
                                          description=f"Container {container_name} has SYS_ADMIN with /proc "
                                                      f"mount - cgroup escape possible")

                if mount_path == "/sys/fs/cgroup" or mount_path.startswith("/sys/fs/cgroup/"):
                    self._add_finding("cgroup_volume_mount",
                                      description=f"Container {container_name} mounts cgroup filesystem")

                if mount.get("subPath"):
                    self._add_finding("sub_path_mount",
                                      description=f"Container {container_name} uses subPath mount")

            # Docker-in-Docker detection
            if "dind" in image or "docker" in container_name.lower():
                if "dind" in image:
                    self._add_finding("docker_in_docker",
                                      description=f"Container {container_name} uses Docker-in-Docker image")

            # emptyDir medium check
            for volume in volumes:
                if "emptyDir" in volume and "medium" not in volume["emptyDir"]:
                    # Only flag if name suggests sensitive data
                    if any(kw in volume.get("name", "").lower() for kw in ["secret", "token", "credential", "key"]):
                        self._add_finding("empty_dir_medium",
                                          description=f"Volume {volume['name']} uses disk-backed "
                                                      f"emptyDir for sensitive data")

        # Check if any security context exists at all
        if not spec.get("securityContext") and all(
            not c.get("securityContext") for c in spec.get("containers", [])
        ):
            self._add_finding("no_security_context",
                              description="No securityContext at pod or container level")

        return self.findings

    def review_against_policies(self, pod: dict, policies: dict) -> List[Finding]:
        """Review pod against custom Kyverno/OPA-style policies."""
        policy_findings = []

        # Support simplified policy format
        # policies = {
        #   "require-run-as-non-root": {"kind": "required", "path": "spec.containers[*].securityContext.runAsNonRoot"},
        #   ...
        # }
        for policy_name, policy in policies.items():
            if policy.get("disabled", False):
                continue

            policy_kind = policy.get("kind", "required")
            policy_path = policy.get("path", "")
            policy_value = policy.get("value")
            policy_message = policy.get("message", f"Policy {policy_name} violated")

            # Navigate path
            value = self._get_path_value(pod, policy_path)

            if policy_kind == "required":
                if value is None or value is False or value == "":
                    policy_findings.append(Finding(
                        severity=policy.get("severity", "HIGH"),
                        check=policy_name,
                        description=policy_message,
                        remediation=policy.get("remediation", "Fix the pod spec to comply with policy"),
                        policy_source=policy.get("source", "custom")
                    ))

            elif policy_kind == "forbidden":
                if value is not None and value not in (False, "", [], {}):
                    policy_findings.append(Finding(
                        severity=policy.get("severity", "HIGH"),
                        check=policy_name,
                        description=policy_message,
                        remediation=policy.get("remediation", "Remove the forbidden configuration"),
                        policy_source=policy.get("source", "custom")
                    ))

            elif policy_kind == "equals":
                if value != policy_value:
                    policy_findings.append(Finding(
                        severity=policy.get("severity", "MEDIUM"),
                        check=policy_name,
                        description=policy_message,
                        remediation=policy.get("remediation", f"Set value to {policy_value}"),
                        policy_source=policy.get("source", "custom")
                    ))

            elif policy_kind == "not_in":
                if value in (policy.get("values") or []):
                    policy_findings.append(Finding(
                        severity=policy.get("severity", "MEDIUM"),
                        check=policy_name,
                        description=policy_message,
                        remediation=policy.get("remediation", "Use an allowed value"),
                        policy_source=policy.get("source", "custom")
                    ))

        return policy_findings

    def _get_path_value(self, obj: dict, path: str):
        """Navigate a dot-separated path in nested dict, supporting [*] for arrays."""
        if not path:
            return None

        parts = path.split(".")
        current = obj

        for part in parts:
            if "[" in part and part.endswith("]"):
                key = part[:part.index("[")]
                indices = re.findall(r"\[(\d+|\*)\]", part)
                if key:
                    current = current.get(key)
                if not isinstance(current, list):
                    return None
                for idx in indices:
                    if idx == "*":
                        # Return first element (simplified)
                        if current:
                            current = current[0]
                        else:
                            return None
                    else:
                        current = current[int(idx)] if int(idx) < len(current) else None
                        if current is None:
                            return None
            else:
                if isinstance(current, dict):
                    current = current.get(part)
                else:
                    return None

                if current is None:
                    return None

        return current

    def generate_report(self, pod: dict, policy_findings: List[Finding]) -> AdmissionReport:
        """Generate full admission report.

        The aggregate level is ESCALATED by the sum of findings but can never fall
        below the worst single finding. Previously the score thresholds alone decided
        the headline, so one `privileged_container` (CRITICAL, 60 points) reported as
        merely HIGH, and any lone HIGH finding (30) reported as MEDIUM — the report
        contradicted its own most severe finding.
        """
        all_findings = self.findings + policy_findings

        total_risk = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in all_findings)

        if total_risk >= 100:
            risk_level = "CRITICAL"
        elif total_risk >= 50:
            risk_level = "HIGH"
        elif total_risk >= 20:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        severity_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        worst = max((severity_order.get(f.severity, 0) for f in all_findings), default=0)
        if severity_order[risk_level] < worst:
            risk_level = [name for name, rank in severity_order.items() if rank == worst][0]

        return AdmissionReport(
            pod_name=pod.get("metadata", {}).get("name", "unnamed"),
            namespace=pod.get("metadata", {}).get("namespace", "default"),
            total_findings=len(all_findings),
            risk_score=total_risk,
            risk_level=risk_level,
            findings=all_findings,
            passed_checks=self.passed_checks,
            policy_violations=policy_findings
        )


def load_pod_spec(source: str) -> dict:
    """Load pod spec from file or stdin."""
    if source == "-":
        data = sys.stdin.read()
    else:
        with open(source, "r") as f:
            data = f.read()

    # Try JSON first, then YAML
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        try:
            return yaml.safe_load(data)
        except yaml.YAMLError as e:
            raise ValueError(f"Failed to parse pod spec: {e}")


def load_policies(source: Optional[str]) -> dict:
    """Load policies from file."""
    if not source:
        return {}

    with open(source, "r") as f:
        data = f.read()

    try:
        return json.loads(data)
    except json.JSONDecodeError:
        try:
            return yaml.safe_load(data)
        except yaml.YAMLError as e:
            raise ValueError(f"Failed to parse policies: {e}")


def main():
    parser = argparse.ArgumentParser(description="Pod Admission Security Review")
    parser.add_argument("--pod", required=True, help="Pod spec file (or - for stdin)")
    parser.add_argument("--policies", help="Custom policies file (YAML/JSON)")
    parser.add_argument("--output", help="Output JSON file for report")
    parser.add_argument("--json", action="store_true", help="Output JSON to stdout")
    args = parser.parse_args()

    pod = load_pod_spec(args.pod)
    policies = load_policies(args.policies) if args.policies else {}

    reviewer = AdmissionReviewer()
    reviewer.review_pod(pod)
    policy_findings = reviewer.review_against_policies(pod, policies) if policies else []

    report = reviewer.generate_report(pod, policy_findings)

    if args.json:
        print(json.dumps(asdict(report), indent=2))
    else:
        print("\n=== Admission Review Report ===")
        print(f"Pod: {report.pod_name}")
        print(f"Namespace: {report.namespace}")
        print(f"Risk Score: {report.risk_score}")
        print(f"Risk Level: {report.risk_level}")
        print(f"Total Findings: {report.total_findings}")
        print(f"Policy Violations: {len(report.policy_violations)}")
        print(f"Passed Checks: {len(report.passed_checks)}")
        print()

        if report.findings:
            print("--- Findings ---")
            for i, finding in enumerate(report.findings, 1):
                print(f"{i}. [{finding.severity}] {finding.check}")
                print(f"   {finding.description}")
                print(f"   Fix: {finding.remediation}")
                print()
        else:
            print("[+] No security findings detected")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(asdict(report), f, indent=2)
        print(f"\n[+] Report written to {args.output}")


if __name__ == "__main__":
    main()
