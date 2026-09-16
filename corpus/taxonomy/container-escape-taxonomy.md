# Container Escape Taxonomy

## Overview
Systematic classification of container escape techniques organized by attack surface, privilege requirement, and MITRE ATT&CK mapping.

## Categories

### 1. cgroup release_agent Abuse
- **Technique**: Exploit cgroup v1 `release_agent` to execute host commands when cgroup empties
- **Prerequisites**: CAP_SYS_ADMIN in container, cgroup v1 mounted, write access to cgroup hierarchy
- **MITRE**: T1611 (Escape to Host), T1068 (Exploitation for Privilege Escalation)
- **Detection**: Monitor `release_agent` writes, cgroup v1 mount presence
- **Mitigation**: Use cgroup v2 only, disable `release_agent`, run containers with `--cgroupns=host` carefully

### 2. proc pidfd_getfd / pidfd_open Abuse
- **Technique**: Use `pidfd_getfd(2)` / `pidfd_open(2)` to steal file descriptors from host processes
- **Prerequisites**: CAP_SYS_PTRACE or PTRACE_MODE_ATTACH, access to host PID namespace
- **MITRE**: T1055 (Process Injection), T1611
- **Detection**: Audit `pidfd_getfd` syscalls, monitor cross-namespace ptrace
- **Mitigation**: Drop CAP_SYS_PTRACE, use user namespaces, seccomp deny `pidfd_getfd`

### 3. Kubernetes RBAC Escalation
- **Technique**: Abuse excessive RBAC permissions (impersonate, bind, escalate) to gain cluster-admin
- **Prerequisites**: Compromised pod/service account with permissive Role/ClusterRole
- **MITRE**: T1078 (Valid Accounts), T1611
- **Detection**: Audit RBAC changes, anomalous impersonation requests, privilege escalation bindings
- **Mitigation**: Least-privilege RBAC, PodSecurity Standards, admission controllers (Kyverno/OPA)

### 4. containerd / cri-o Socket Abuse
- **Technique**: Access container runtime Unix sockets (`/run/containerd/containerd.sock`, `/run/crio/crio.sock`) to create privileged containers
- **Prerequisites**: Socket mounted into container, or network access to socket via sidecar
- **MITRE**: T1611, T1525 (Implant Container Image)
- **Detection**: Monitor socket connections, unexpected container create calls
- **Mitigation**: Don't mount runtime sockets, use CRI proxy with authz, SELinux/AppArmor

### 5. runc CVE Replay (CVE-2019-5736, CVE-2024-21626, etc.)
- **Technique**: Exploit runc vulnerabilities to break out via malicious image or runtime manipulation
- **Prerequisites**: Vulnerable runc version, ability to run/control container image
- **MITRE**: T1611, T1190 (Exploit Public-Facing Application)
- **Detection**: Image scanning, runtime version monitoring, Falco rules for runc anomalies
- **Mitigation**: Pin runc version, update regularly, use gVisor/Kata Containers for hard isolation

### 6. eBPF Probe Injection
- **Technique**: Load malicious eBPF programs to trace/hook kernel functions, exfiltrate data, or modify behavior
- **Prerequisites**: CAP_BPF, CAP_SYS_ADMIN, BPF JIT enabled, kernel >= 5.8
- **MITRE**: T1556.002 (Password Filter), T1055, T1040 (Network Sniffing)
- **Detection**: Monitor `bpf()` syscall, BPF program loads, unusual map access
- **Mitigation**: Restrict CAP_BPF, sign BPF programs, kernel lockdown mode

### 7. Host Path / Volume Mount Escape
- **Technique**: Mount sensitive host paths (`/`, `/proc`, `/sys`, `/var/run/docker.sock`) and manipulate host
- **Prerequisites**: Pod spec allows hostPath, privileged pod, or PSP/PodSecurity bypass
- **MITRE**: T1611, T1005 (Data from Local System)
- **Detection**: Admission review for hostPath, runtime Falco rules for sensitive mount access
- **Mitigation**: PodSecurity Standards Restricted, deny hostPath, read-only root filesystem

### 8. Kernel Exploit via Syscall Exposure
- **Technique**: Trigger kernel vulnerabilities via exposed syscalls (io_uring, userfaultfd, etc.)
- **Prerequisites**: Vulnerable kernel, syscall not blocked by seccomp
- **MITRE**: T1068, T1611
- **Detection**: Seccomp notifications, kernel crash logs, CVE tracking
- **Mitigation**: Seccomp profiles, kernel updates, gVisor/Kata for syscall virtualization

### 9. Namespace Escape via /proc/self/ns/
- **Technique**: Manipulate namespace symlinks in `/proc/self/ns/` to enter host namespaces
- **Prerequisites**: Access to host proc, CAP_SYS_ADMIN for setns
- **MITRE**: T1611
- **Detection**: Monitor `setns` calls, namespace transitions
- **Mitigation**: Hide host proc (`hidepid=2`), drop CAP_SYS_ADMIN

### 10. Capability-Based Escape Chains
- **Technique**: Combine CAP_DAC_OVERRIDE, CAP_SYS_MODULE, CAP_SYS_RAWIO, etc. for escape
- **Prerequisites**: Over-privileged container capability set
- **MITRE**: T1611, T1068
- **Detection**: Audit container capabilities, runtime capability enforcement
- **Mitigation**: Drop ALL capabilities, add only required, use capability bounding set

## Risk Scoring Framework

| Technique | Prevalence | Impact | Detectability | Overall Risk |
|-----------|-----------|--------|---------------|--------------|
| cgroup release_agent | Medium | Critical | High | **Critical** |
| pidfd_getfd abuse | Low | Critical | Medium | **High** |
| K8s RBAC escalation | High | Critical | High | **Critical** |
| containerd/cri-o socket | Medium | Critical | Medium | **High** |
| runc CVE replay | Low | Critical | Low | **High** |
| eBPF probe injection | Low | High | Low | **Medium** |
| Host path mount | High | High | High | **High** |
| Kernel syscall exploit | Low | Critical | Low | **High** |
| Namespace /proc escape | Low | High | Medium | **Medium** |
| Capability chains | Medium | High | High | **High** |

## References
- MITRE ATT&CK: T1611, T1068, T1055, T1078, T1525, T1190, T1005
- NIST SP 800-190 (Application Container Security Guide)
- Kubernetes Threat Matrix (Microsoft)
- Container Escape Demystified (Felix Wilhelm, Google CTF)
