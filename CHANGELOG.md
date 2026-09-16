# Changelog

All notable changes to the Cloud/Container Escape Corpus.

## [1.0.0] — 2026-09-16

### Added

- **Taxonomy**: 10 container escape techniques (CE-001 … CE-010), risk-scored
  and MITRE-mapped, in human (`container-escape-taxonomy.md`) and machine
  (`taxonomy.json`) form
- **Playbooks**: per-technique guides with prerequisites, attack paths, PoC
  sketches, detection, and mitigation (`corpus/techniques/`)
- **Detection content**: 11 Sigma rules + 8 Falco rules with a machine-readable
  rule→technique index (`corpus/detection/`)
- **Side-channel inventory**: /proc, /sys, cgroup v2, namespace, and
  seccomp-notch leakage map in human (`side-channel-inventory.md`) and machine
  (`side-channels.json`, SC-001…SC-010) form with JSON Schema
- **Tools** (pip-installable `escape_corpus` package):
  - `image-diff` — risk-weighted OCI image tag delta (hardlink-aware,
    preserves setuid + file-capability signals)
  - `runtime-baseline` — hash-chained runtime drift baseline/verify/monitor
  - `admission-review` — 40+ pod security checks + simplified
    Kyverno/OPA-style custom policies
  - `escape-corpus` — unified CLI with `techniques`, `rules`, `side-channels`,
    `schemas`, `validate` subcommands
- **JSON Schemas** (draft 2020-12) for taxonomy, side-channels, and all tool
  outputs (`schemas/`)
- **Lab**: kind-based setup guide with vulnerable pod matrix
  (`corpus/lab/`)
- **Tests**: 6/6 passing unit suite; CI with a `live-tools` job that runs
  `runtime-baseline` against real Docker containers and asserts admission
  review outcomes on runners

### Verified

- Live against kind v1.37.0 (containerd 2.3.4, docker 29.8.0): baseline/verify/
  monitor clean; cross-container SYS_PTRACE verify → CRITICAL on capabilities
  and all 8 namespace inodes
- Live image diffs against docker.io: busybox +4/-0/~11 LOW; nginx +6/-0/~714
  MEDIUM with `/etc/shadow` and User-change flags
- Live admission review on running pods matches dry-run scores exactly
  (CRITICAL/725 vulnerable, MEDIUM/20 secure)
