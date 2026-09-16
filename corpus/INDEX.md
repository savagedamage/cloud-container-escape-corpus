# Corpus Index

Master index for the Cloud/Container Escape Corpus. Human-first; the machine
equivalent is [`taxonomy.json`](taxonomy/taxonomy.json) + [`index.yaml`](index.yaml).

## Start here

| You want to… | Go to |
|---|---|
| Understand what this is | [`../README.md`](../README.md) |
| Get the 10-technique overview | [`taxonomy/container-escape-taxonomy.md`](taxonomy/container-escape-taxonomy.md) |
| Map information leakage paths | [`side-channels/side-channel-inventory.md`](side-channels/side-channel-inventory.md) |
| Stand up a lab | [`lab/LAB-SETUP.md`](lab/LAB-SETUP.md) |
| Browse techniques (CLI) | `escape-corpus techniques` |
| Browse detection rules (CLI) | `escape-corpus rules` |
| Browse side-channels (CLI) | `escape-corpus side-channels` |

## Techniques (CE-001 … CE-010)

| ID | Technique | Risk | Playbook |
|---|---|---|---|
| CE-001 | cgroup release_agent abuse | CRITICAL | [techniques/CE-001](techniques/CE-001-cgroup-release-agent.md) |
| CE-002 | pidfd_getfd / pidfd_open abuse | HIGH | [techniques/CE-002](techniques/CE-002-pidfd-getfd.md) |
| CE-003 | Kubernetes RBAC escalation | CRITICAL | [techniques/CE-003](techniques/CE-003-k8s-rbac-escalation.md) |
| CE-004 | Container runtime socket abuse | HIGH | [techniques/CE-004](techniques/CE-004-runtime-socket-abuse.md) |
| CE-005 | runc CVE replay | HIGH | [techniques/CE-005](techniques/CE-005-runc-cve-replay.md) |
| CE-006 | eBPF probe injection | MEDIUM | [techniques/CE-006](techniques/CE-006-ebpf-probe-injection.md) |
| CE-007 | Host path / volume mount escape | HIGH | [techniques/CE-007](techniques/CE-007-hostpath-volume-escape.md) |
| CE-008 | Kernel exploit via syscall exposure | HIGH | [techniques/CE-008](techniques/CE-008-kernel-syscall-exploit.md) |
| CE-009 | Namespace escape via /proc/self/ns | MEDIUM | [techniques/CE-009](techniques/CE-009-namespace-escape.md) |
| CE-010 | Capability-based escape chains | HIGH | [techniques/CE-010](techniques/CE-010-capability-chains.md) |

## Detection rules

- 11 Sigma rules → [`detection/sigma/`](detection/sigma/) (index: [detection/index.yaml](detection/index.yaml))
- 8 Falco rules → [`detection/falco/`](detection/falco/)

Each playbook's "Detection" section names the rules that cover it; each rule
declares its `detects:` technique IDs in the detection index.

## Tools

- `image-diff` — risk-weighted OCI tag delta
- `runtime-baseline` — hash-chained runtime drift baseline/verify/monitor
- `admission-review` — 40+ pod security checks + custom policies
- `escape-corpus` — unified CLI (also: `techniques`, `rules`, `schemas`, `validate`)

## Schemas

Machine-readable contracts for every structured output in [`../schemas/`](../schemas/).

## Machine-readable layer

| File | Purpose |
|---|---|
| `taxonomy/taxonomy.json` | Full structured taxonomy: techniques, MITRE mapping, risk, rule links |
| `side-channels/side-channels.json` | 10 leakage surfaces: paths, syscalls, risk, mitigations, detection |
| `index.yaml` | Entry points, tool inventory, schema list |
| `detection/index.yaml` | Rule → technique mapping |
| `../schemas/*.schema.json` | JSON Schemas (draft 2020-12) for taxonomy, side-channels, and all tool outputs |

Run `escape-corpus validate` to cross-check consistency between all of these.
