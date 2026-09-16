# Container Escape Taxonomy

## Overview

Systematic classification of container escape techniques organized by attack
surface, privilege requirement, and MITRE ATT&CK mapping.

This document is the human-readable view. The machine-readable twin is
[`taxonomy.json`](taxonomy.json) (same IDs, validated by JSON Schema — see
[`schemas/taxonomy.schema.json`](../../schemas/taxonomy.schema.json)). Each
technique has a full playbook under [`../techniques/`](../techniques/).

## Technique index

| ID | Technique | Category | MITRE | Risk | Playbook | Detection rules |
|---|---|---|---|---|---|---|
| CE-001 | cgroup release_agent abuse | kernel/cgroup | T1611, T1068 | CRITICAL | [playbook](../techniques/CE-001-cgroup-release-agent.md) | SIGMA-001, FALCO-001 |
| CE-002 | pidfd_getfd / pidfd_open abuse | kernel/proc | T1055, T1611 | HIGH | [playbook](../techniques/CE-002-pidfd-getfd.md) | SIGMA-002, FALCO-002 |
| CE-003 | Kubernetes RBAC escalation | orchestration/rbac | T1078, T1611 | CRITICAL | [playbook](../techniques/CE-003-k8s-rbac-escalation.md) | SIGMA-010 |
| CE-004 | Container runtime socket abuse | runtime/socket | T1611, T1525 | HIGH | [playbook](../techniques/CE-004-runtime-socket-abuse.md) | SIGMA-004, FALCO-004 |
| CE-005 | runc CVE replay | runtime/runc | T1611, T1190 | HIGH | [playbook](../techniques/CE-005-runc-cve-replay.md) | SIGMA-005, FALCO-005 |
| CE-006 | eBPF probe injection | kernel/ebpf | T1556.002, T1055, T1040 | MEDIUM | [playbook](../techniques/CE-006-ebpf-probe-injection.md) | SIGMA-006, FALCO-006 |
| CE-007 | Host path / volume mount escape | orchestration/volumes | T1611, T1005 | HIGH | [playbook](../techniques/CE-007-hostpath-volume-escape.md) | SIGMA-003, SIGMA-008, SIGMA-009, FALCO-003, FALCO-008 |
| CE-008 | Kernel exploit via syscall exposure | kernel/syscalls | T1068, T1611 | HIGH | [playbook](../techniques/CE-008-kernel-syscall-exploit.md) | SIGMA-011 |
| CE-009 | Namespace escape via /proc/self/ns | kernel/namespaces | T1611 | MEDIUM | [playbook](../techniques/CE-009-namespace-escape.md) | SIGMA-003, FALCO-003 |
| CE-010 | Capability-based escape chains | kernel/capabilities | T1611, T1068 | HIGH | [playbook](../techniques/CE-010-capability-chains.md) | SIGMA-007, SIGMA-008, FALCO-007 |

## Risk scoring

Four axes per technique: **prevalence** (how common in real clusters),
**impact** (worst-case outcome), **detectability** (how well existing tooling
catches it), and **overall** (weighted roll-up):

| overall | when |
|---|---|
| CRITICAL | high impact AND high prevalence, regardless of detectability |
| HIGH | critical impact but low prevalence or low detectability |
| MEDIUM | high impact, low prevalence, low detectability — hard to trigger but hard to see |
| LOW | limited impact or fully mitigated by default posture |

## MITRE ATT&CK coverage

| ATT&CK | Techniques |
|---|---|
| T1611 (Container Escape) | CE-001, CE-002, CE-003, CE-004, CE-005, CE-007, CE-008, CE-009, CE-010 |
| T1068 (Exploitation for Privilege Escalation) | CE-001, CE-008, CE-010 |
| T1055 (Process Injection) | CE-002, CE-006 |
| T1078 (Valid Accounts) | CE-003 |
| T1525 (Implant Container Image) | CE-004 |
| T1190 (Exploit Public-Facing Application) | CE-005 |
| T1040 (Network Sniffing) | CE-006 |
| T1556.002 (Password Filter) | CE-006 |
| T1005 (Data from Local System) | CE-007 |

## Detection coverage

| Technique | Sigma | Falco | Lab manifest |
|---|---|---|---|
| CE-001 | ✓ | ✓ | privileged-escape-pod.yaml |
| CE-002 | ✓ | ✓ | — |
| CE-003 | ✓ | — | — |
| CE-004 | ✓ | ✓ | docker-socket-pod.yaml |
| CE-005 | ✓ | ✓ | — |
| CE-006 | ✓ | ✓ | privileged-escape-pod.yaml |
| CE-007 | ✓ (3 rules) | ✓ (2 rules) | hostpath-proc-pod.yaml |
| CE-008 | ✓ | — | — |
| CE-009 | ✓ | ✓ | hostpath-proc-pod.yaml |
| CE-010 | ✓ (2 rules) | ✓ | privileged-escape-pod.yaml |

Gaps (no Falco coverage): CE-003, CE-008 — by design: RBAC escalation is best
caught in Kubernetes audit logs (SIGMA-010), and kernel syscall exploitation is
best caught by seccomp notify + kernel patch management rather than runtime rules.

## References

- MITRE ATT&CK: T1611, T1068, T1055, T1078, T1525, T1190, T1005, T1040, T1556.002
- NIST SP 800-190 (Application Container Security Guide)
- Kubernetes Threat Matrix (Microsoft)
- Container Escape Demystified (Felix Wilhelm, Google CTF)
