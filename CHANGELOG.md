# Changelog

All notable changes to the Cloud/Container Escape Corpus.

## [1.2.0] — 2026-09-19

Platform correctness, RPM support, and a severity-calibration fix. Five more real
defects found by testing against real registries and real distributions rather than
synthetic fixtures.

### Added

- **Platform-aware image diff**: `--platform OS/ARCH[/VARIANT]`, plus
  `--platform-old`/`--platform-new` for auditing a migration. `crane` resolves to the
  **host** architecture by default, so the previous behaviour silently diffed the
  wrong variant of a multi-arch image. Comparing two *different* architectures is
  now detected as a meaningless delta (scored, with guidance) unless it was
  explicitly requested, in which case it is labelled as a migration audit.
- **RPM package inventory**: `rpmdb.sqlite` headers are parsed directly with the
  standard library (no rpm/py binding), so RHEL/CentOS/Rocky/Fedora/AlmaLinux images
  now report package deltas instead of "unavailable". Verified **118/118** packages
  against rockylinux:9-minimal (`bash 5.1.8-6.el9_1`, `openssl-libs 1:3.0.7-24.el9`).
  The legacy Berkeley-DB rpmdb still reports unavailable rather than empty.
- **cgroup v1 support in `runtime-baseline`**: v1 hosts were detected but never read
  (the code only knew v2 file names), so resource limits came back `None` and
  resource drift was invisible. v1 read paths, controller extraction from
  `/proc/self/cgroup`, and `cpu.cfs_quota_us`/`cfs_period_us` normalisation added.
- **Precision tests** (`tests/test_precision.py`): pods built to the Pod Security
  Standards "restricted" profile must not be flagged HIGH/CRITICAL, across eight
  field permutations, while a single dangerous field on such a pod still is.
- **Severity-calibration tests** (`tests/test_severity_calibration.py`): pins the
  "no understatement" invariant and the score ordering between pod classes that the
  labels saturate.

### Fixed

- **Report level could understate its own worst finding.** A pod whose only problem
  was `privileged: true` (a CRITICAL check worth 60 points) reported as merely HIGH,
  and any lone HIGH finding (30 points) reported as MEDIUM. The aggregate level is
  now escalated by the finding sum but can never fall below the worst single finding.
- **cgroup resource-limit drift was never compared.** The detector checked only the
  cgroup path and version — raising memory/CPU/PID limits on a running container went
  undetected on *both* cgroup generations. Limits and controllers are now compared,
  with a direction ("Memory limit raised: 512MiB → 2GiB").
- **Crash on mode-0000 files.** `/etc/shadow-` is mode `0000` in every RHEL image, so
  the flattener could not read back the file it had just written
  (`PermissionError` on any `rockylinux`/`centos`/`almalinux` image). The on-disk copy
  is now readable while the *authoritative* mode is recorded from the tar member —
  the setuid signal is unaffected (regression-tested).
- **Registry errors hid the actionable part.** A pull failure reported
  `Failed to pull <image>` and discarded the runtime's message; it now surfaces
  `no child with platform linux/amd64 in index ...` and says to pass `--platform`.
- **Integer rpm header tags decoded their entry count, not their value**, which made
  `epoch 0` indistinguishable from `epoch 1`, and the source-rpm filter raised
  `KeyError` when a header had no ARCH tag.

### Changed

- `image-diff` output gains `platform`, `platform_old`, `platform_new`,
  `architecture_old`, `architecture_new`, `architecture_mismatch` and
  `intentional_architecture_change` (schema updated). `--platform` is forwarded by
  the unified `escape-corpus` CLI.
- Tests **193 → 254**, coverage **85% → 86%**; `escape_corpus/packages.py` at 99%.
- BadPods benchmark regenerated: still **128/128 flagged**, with recalibrated
  severity attribution.

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
