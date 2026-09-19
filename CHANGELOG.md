# Changelog

All notable changes to the Cloud/Container Escape Corpus.

## [1.1.0] — 2026-09-19

Completeness and evidence pass: the corpus's own claims became testable, and the
cloud half of its name became true.

### Added

- **Cloud techniques**: `CE-011` IMDS instance-metadata credential theft and
  `CE-012` workload-identity token theft — playbooks, taxonomy entries, and
  4 new detection rules (SIGMA-012/013, FALCO-009/010). 12 techniques total.
- **Package-level image delta** (`escape_corpus/packages.py`): `image-diff` now
  reports dpkg/apk `added`/`removed`/`upgraded` alongside the file delta, so a
  noisy file count resolves to a cause (nginx 1.24→1.25 reads as the
  bullseye→bookworm base change: `libssl1.1 → libssl3`, 120 packages upgraded).
  RPM images report the inventory as *unavailable* rather than empty. Stdlib-only —
  no syft/grype binary required.
- **MCP server** (`escape-corpus-mcp`, `pip install '.[mcp]'`): 8 tools and
  4 resources exposing the corpus to agents; read-only with respect to
  infrastructure. Verified through a real MCP client session.
- **Agent skill** (`skill/SKILL.md`): how to use the corpus, plus the ten
  hard-won rules (Falco priority vocabulary, Sigma tag format, component-wise
  path matching, fstype-based mount detection, `parse_intermixed_args`, …).
- **BadPods benchmark** (`scripts/benchmark_badpods.py`): repeatable recall
  measurement against BishopFox/badPods — **128/128 flagged**, with per-level
  severity gradient and per-check attribution shipped in
  `corpus/benchmarks/`.
- **Lab coverage**: 4 new manifests (cgroup release_agent, eBPF probe injection,
  pidfd_getfd, capability chains) + idempotent `corpus/lab/up.sh` and
  `corpus/lab/verify.sh`; 7 manifests verified CRITICAL.
- **Docs site**: `mkdocs.yml` + `scripts/build_docs.py`, which generates the site
  from the canonical files (no duplicated prose) and builds `--strict` clean.
- **`VERIFICATION.md`**: every claim paired with the command and observed output.
- **`scripts/verify.sh`**: one command reproducing all verification claims,
  `--live` for registry/docker checks.
- **`docs/roadmap.md`**: deliberate non-goals (Windows containers, weaponised
  tooling, live mutation) and known limitations, stated rather than hidden.
- CI: lint gate, 80% coverage floor, `sigma check`, MCP tests, docs build, and a
  4-version Python matrix (3.10–3.13).

### Fixed

- **Four real defects found by the new tests** (none caught by review):
  - host `/proc`/`/sys` bind-mount detection keyed on the mount *source* rather
    than the fstype, so it never fired for the bind case
  - `/etc/kubernetes` matched the shorter `/etc` key first, reporting the
    less-specific finding
  - `hostPath` matching used unbounded `startswith`, so `/etcfoo` matched `/etc`
  - `review_pod` returned nested dataclasses that did not survive JSON
    serialization
- **Three detection-rule defects** caught by `sigma check` / the Falco schema:
  an invented `attack.escape` tag, an invalid `attack.privilege_escalation` tag,
  and `priority: HIGH` (Falco has no such level — it is `WARNING`).
- **Detection index vocabulary** normalised: `level` is now the corpus severity
  for both engines, with engine-native priorities compared through an explicit
  mapping.
- **Packaging**: `corpus/benchmarks/` and `docs/roadmap.md` were missing from the
  installed tree; caught by installing into a clean virtualenv.
- **CI argparse failure** on Python ≤3.12 (`nargs="*"` positional plus
  interspersed flags): switched to `parse_intermixed_args()` with a regression
  test, and reproduced on a real 3.11 interpreter before fixing.

### Changed

- **Lab bring-up now requires explicit consent.** `corpus/lab/up.sh` refuses to
  deploy the deliberately vulnerable fixtures without `--yes` (or `LAB_CONFIRM=1`),
  printing what it would do and exiting non-zero *before* the first cluster
  mutation; on a terminal it prompts. Added because the previous version only
  carried a header comment saying "isolated lab only", and an automated caller
  deployed the privileged + hostPID fixtures onto a daily-driver host without
  hesitating — a comment is not a control. `LAB-SETUP.md` documents the flag and
  the teardown command.
- **Test coverage 20% → 85%** (193 tests, from 6), with an enforced 80% floor.
  New suites: synthetic-OCI fixtures for `image_diff`, a canned-runtime harness
  for `runtime_baseline`, the CLI validation gate, the admission policy engine,
  detection-rule validation, the benchmark harness, and the MCP server.
- `escape_corpus/corpus_data.py` extracted as the single source of truth for
  corpus paths and loading, shared by the CLI and the MCP server.
- `ruff` configured and run clean (310 findings → 0).
- README restructured around the measured verification record.

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
