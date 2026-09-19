# Verification record

Every claim in this repository is backed by a command that was run and output that
was observed. This file records what was executed, when, and with what result.

Reproduce everything: `bash scripts/verify.sh` (offline) or
`bash scripts/verify.sh --live` (adds registry pulls and a real container).

**Last full run: 2026-09-19 (UTC)** · result **11/11 PASS**

This file records two rounds: the initial evidence pass (v1.1.0) and the platform /
distribution / calibration round (v1.2.0). Numbers are updated to the current state.

## Environment

| | |
|---|---|
| Host | Linux, kernel 7.2.4-arch1-2 |
| Python (local suite) | 3.12 / 3.14.7 (both) |
| Python (CI matrix) | 3.10, 3.11, 3.12, 3.13 |
| docker | 29.8.0, storage driver `overlayfs` |
| kind / Kubernetes | kind v0.33.0, k8s v1.37.0, containerd 2.3.4 |
| crane | v0.22.1 (registry pulls for `image-diff`) |
| python@3.11.16 | installed via mise, used to reproduce the CI-only argparse failure |

## 1. Test suite and coverage

```
$ python3 -m pytest tests/ -q --cov=escape_corpus --cov-report=term
254 passed in 2.71s
TOTAL   1662    232    86%     Required test coverage of 80.0% reached.
```

Coverage went from **20% → 86%** overall (`cli.py` 0% → 89%, `image_diff.py` 0% → 85%,
`runtime_baseline.py` 21% → 85%, `packages.py` 99%). The 80% floor is enforced in
`pyproject.toml`, so the build fails rather than degrading silently.

## 2. Lint

```
$ ruff check .
All checks passed!
```

Configured in `pyproject.toml`: line-length 120, rules `E, F, W, I, B, UP`.
(Tests are exempt from `E501` so long fixture strings stay readable.) The initial
run reported 310 findings; all were resolved, not suppressed — only `E501` is
excluded anywhere, and only for `tests/`.

## 3. Corpus internal consistency

```
$ escape-corpus validate
OK — 12 techniques, 23 rule refs, 10 side-channel surfaces, 6 schemas,
cross-references consistent (jsonschema deep-check)
```

`validate` is a real gate, not a file-existence check: it verifies every technique's
`guide` resolves, every `detection_rule_ids` entry exists in the detection index,
every rule's `detects` points at a real technique, every schema parses, and the
machine artifacts validate against their schemas. Its failure path is tested
(`tests/test_cli.py`) — a gate that cannot fail is not a gate.

## 4. Detection rules — engine-validated

```
$ sigma check corpus/detection/sigma/
Found 0 errors, 0 condition errors and 0 issues.
```

13 Sigma rules validated by pySigma (`sigma-cli`). This check found three real
defects which are now fixed:

| Defect | Why it mattered |
|---|---|
| `attack.escape` tag | Not a real ATT&CK reference — invented tag |
| `attack.privilege_escalation` | Wrong separator; pySigma expects `attack.privilege-escalation` |
| `priority: HIGH` (falco-008) | Falco's vocabulary has no `HIGH` — it is `WARNING`. A silently non-matching priority |

Falco rules are **schema-validated, not engine-executed**: the `falco` binary is not
available in this environment, so `schemas/falco-rule.schema.json` plus
`tests/test_detection_rules.py` enforce structure, priority vocabulary, and
index cross-references. This limitation is stated rather than papered over.

## 5. MCP server

```
$ python3 -m pytest tests/test_mcp_server.py -q
16 passed
$ # client round-trip: 8 tools, 4 resources
tools: ['baseline_snapshot', 'diff_images', 'get_technique', 'list_detection_rules',
        'list_side_channels', 'list_techniques', 'review_pod', 'validate_corpus']
resources: ['corpus://detection-index', 'corpus://index', 'corpus://side-channels',
            'corpus://taxonomy']
```

Verified through a real `fastmcp.Client` session (registration, argument validation,
serialization), not by calling the underlying functions directly.

## 6. Admission review — benchmark and live fixtures

**BadPods benchmark** (`scripts/benchmark_badpods.py`, 128 manifests from
BishopFox/badPods @ `107e5d8`):

| BadPods level | objects | flagged | recall | median score |
|---|---|---|---|---|
| nothing-allowed | 16 | 16 | 100% | 125 |
| hostipc | 16 | 16 | 100% | 155 |
| hostnetwork | 16 | 16 | 100% | 155 |
| hostpath | 16 | 16 | 100% | 245 |
| hostpid | 16 | 16 | 100% | 155 |
| priv | 16 | 16 | 100% | 170 |
| priv-and-hostpid | 16 | 16 | 100% | 200 |
| everything-allowed | 16 | 16 | 100% | 380 |

**128/128 flagged (100% recall)**, with the median score tracking the permission
level. Full output: `corpus/benchmarks/badpods-admission-review.{md,json}`.

Two honest notes about this table:

- **Every level lands at CRITICAL**, including `nothing-allowed`. No CRITICAL-severity
  check fires there — the level comes from *score accumulation* (ten advisory
  findings ≈ 125 points, above the 100 threshold). That is pre-existing behaviour,
  and it means the label saturates on this corpus. The **score** is the signal that
  discriminates, and `tests/test_severity_calibration.py` pins that ordering.
- The medians dropped relative to the first run (e.g. `priv` 365 → 170) because the
  most-specific-path fix removed duplicate findings for a single mount. Recall is
  unaffected; the attribution is now more accurate.

Recall on a maximally hostile corpus is the *easy* half of the evidence — BadPods is
designed to be dangerous, so 100% is the expected floor, and the useful signal is
the gradient in the median scores and the per-level check attribution in the shipped
JSON. Precision against a second, differently-authored corpus is open work
(`docs/roadmap.md`).

**Lab fixtures** — all 7 manifests, verified by running `corpus/lab/verify.sh`
against the live kind cluster:

```
PASS  capability-chain-pod.yaml          risk_level=CRITICAL score=170  findings=11
PASS  cgroup-release-agent-pod.yaml      risk_level=CRITICAL score=380  findings=15
PASS  docker-socket-pod.yaml             risk_level=CRITICAL score=245  findings=12
PASS  ebpf-probe-pod.yaml                risk_level=CRITICAL score=290  findings=13
PASS  hostpath-proc-pod.yaml             risk_level=CRITICAL score=260  findings=12
PASS  pidfd-getfd-pod.yaml               risk_level=CRITICAL score=170  findings=11
PASS  privileged-escape-pod.yaml         risk_level=CRITICAL score=500  findings=17
PASS  runtime-baseline  container=escape-lab-control-plane  No drift detected
```

Earlier live cluster run: escape fixture = CRITICAL/695, secure fixture = MEDIUM/20.
The escape fixture's score moved from 725 to 695 when the most-specific path matcher
stopped reporting a single mount twice.

**The gate actually fails** — a gate that cannot fail is not a gate. A deliberately
compliant pod dropped into `corpus/lab/` was rejected:

```
FAIL  zz-tmp-compliant-pod.yaml          risk_level=LOW      score=15   (expected CRITICAL or HIGH)
[lab-verify] FAILED: 1 check(s) failed
$ bash corpus/lab/verify.sh; echo $?    # -> 1
```

**`up.sh` refuses to deploy without explicit consent** (added after an automated
caller deployed the fixtures onto a daily-driver host, reading past the header
comment that said not to):

```
$ bash corpus/lab/up.sh </dev/null      # no TTY, no flag
[lab-up] WARN: this deploys DELIBERATELY VULNERABLE pods (privileged, hostPID, writable
[lab-up] WARN: cgroup and /lib/modules host mounts) into kind cluster 'escape-lab'.
[lab-up] ERROR: refusing to deploy vulnerable pods without confirmation (stdin is not a terminal).
# exit 1, and 0 pods in the 'vulnerable' namespace afterwards
```

**Fixtures are not left running.** The eight vulnerable pods deployed during
verification were torn down (`kubectl delete pods -n vulnerable --all`), leaving only
the restricted control pod in `secure`. Re-deploy with `up.sh --yes`, which requires
deliberate intent.

## 7. `image-diff` — live registry pulls

| Comparison | Files | Package delta | Result |
|---|---|---|---|
| `busybox:1.35 → 1.36` | +4 −0 ~11 | n/a (no package DB) | LOW (5) |
| `nginx:1.23 → 1.24` | +6 −0 ~714 (6 layers) | n/a | MEDIUM (35) — `/etc/shadow` modified, User change flagged |
| `nginx:1.24 → 1.25` | +829 −1152 ~2652 | dpkg: +26 −19 ^120 | CRITICAL (11035) |

The 1.24 → 1.25 run is the clearest evidence the package delta adds signal: the
file-level view says "2652 files changed", while the package view names the cause —
a Debian **bullseye → bookworm** base change, visible as `libssl1.1 → libssl3`
(the OpenSSL 1.1 → 3 migration), `apt 2.2.4 → 2.6.1`, `curl 7.74 → 7.88`. Trimmed
sample shipped at `corpus/benchmarks/image-diff-nginx-sample.json` and validated
against `schemas/image-diff.schema.json` in CI.

## 8. `runtime-baseline` — live drift detection

```
PASS  baseline -> verify round trip is clean      (docker, alpine:3.19)
```

Earlier on the kind control-plane container:

- baseline → verify: **clean** (rolling hash chain, no false CRITICAL)
- cross-container verify against a `--cap-add SYS_PTRACE` container: **CRITICAL** —
  capability set `0xa80425fb → 0xa80c25fb` (**bit 19 = CAP_SYS_PTRACE**) plus all 8
  namespace inode changes

## 9. Docs site

```
$ python3 scripts/build_docs.py && mkdocs build --strict
Documentation built in 0.46 seconds     (23 HTML pages)
```

`--strict` makes a dangling link a build failure, which is the point: the docs are
**generated** from the canonical files by `scripts/build_docs.py`, so this catches
generator rot rather than duplicating prose that can drift.

## 10. Packaging

```
$ python3 -m venv /tmp/pkgtest2 && /tmp/pkgtest2/bin/pip install .
$ /tmp/pkgtest2/bin/escape-corpus validate
OK — 12 techniques, 23 rule refs, 10 side-channel surfaces, 6 schemas
```

Verified that `corpus/benchmarks/` and `docs/roadmap.md` are present in the installed
tree (`share/escape-corpus/`) — their absence was a real bug caught by installing the
built package into a clean virtualenv rather than testing only from the source tree.

## 11. Platform, distribution and calibration (v1.2.0)

### Multi-architecture correctness

`crane` resolves to the **host** architecture unless told otherwise — verified, not
assumed:

```
$ crane config busybox:1.36 | jq -r .architecture      # no --platform
amd64
$ crane pull --platform linux/arm64 busybox:1.36 arm64.tar   # respects the flag
   pulled config architecture: arm64   (1900032 bytes vs 2210304 for amd64)
```

So an un-flagged diff silently compares the host variant. `--platform` is now passed
to both pulls and both config lookups (asserted in tests), and a *mixed* comparison is
detected:

```
$ escape-corpus image-diff busybox:1.36 busybox:1.36 \
      --platform-old linux/amd64 --platform-new linux/arm64
Platform: linux/amd64 -> linux/arm64 (amd64 -> arm64)  (requested migration)
Files: +1 -1 ~10        Risk score: 25 -> MEDIUM        # no mismatch penalty
```

Versus an *accidental* mismatch, which is scored and explained. A pull that cannot
resolve the platform now says why instead of failing opaquely:

```
RuntimeError: Failed to pull arm64v8/busybox:1.36: Error: no child with platform
linux/amd64 in index arm64v8/busybox:1.36
      This image has no variant for the resolved platform. Pass --platform ...
```

### RPM package inventory

Validated against a **real** rpmdb extracted from `rockylinux:9-minimal` — not a
synthetic fixture, which is how the first implementation's bug was found:

```
Packages rows (sqlite): 118 | parsed: 118
  bash            5.1.8-6.el9_1
  glibc           2.34-83.el9.7
  openssl-libs    1:3.0.7-24.el9     <- epoch decoded from the header VALUE
  rpm             4.16.1.3-25.el9
```

Two bugs surfaced only on real data: the stored header blob has **no magic prefix**
(unlike the on-disk header), so a magic-only parser returned 0 of 118 packages; and
integer tags decoded their entry count rather than their value, making `epoch 0`
indistinguishable from `epoch 1`. A real 25 KB header blob is committed as a fixture
(`tests/fixtures/rpm-blob-bash.bin`, provenance in the test docstring) so the format
contract stays anchored to reality. End to end:

```
$ escape-corpus image-diff rockylinux:9-minimal rockylinux:9
    Packages (rpm): +38 -15 ^ 0     # dnf, binutils, curl-minimal added
```

This run also exposed a crash on **every** RHEL-family image: `/etc/shadow-` is mode
`0000`, so the flattener could not read back the file it had just written
(`PermissionError`). The on-disk copy is now readable while the authoritative mode is
recorded from the tar member, so the setuid signal is unchanged (regression-tested in
`tests/test_image_diff.py`).

### cgroup v1 and resource-limit drift

`runtime-baseline` detected v1 hosts but only knew v2 file names, so every limit came
back `None`. Worse, the detector compared only the cgroup *path* and *version*. Both
are fixed, and the tests assert the property that was silently absent:

```
TestCgroupV1::test_limits_are_read_from_v1_paths            PASS
TestCgroupV1::test_memory_limit_change_on_v1_is_detected_as_drift  PASS
```

### Severity calibration

A report could understate its own worst finding:

| pod | before | after |
|---|---|---|
| `privileged: true` only | **HIGH** | **CRITICAL** |
| `hostPID: true` only | **MEDIUM** | **HIGH** |
| `hostNetwork: true` only | **MEDIUM** | **HIGH** |
| restricted-profile pod | MEDIUM | MEDIUM (unchanged) |

The aggregate is still escalated by the score sum but can no longer fall below the
worst single finding. `tests/test_severity_calibration.py` pins the invariant at every
severity level and the score ordering that survives label saturation.

### Precision against a documented spec

Eight permutations of a pod built to the Pod Security Standards "restricted" profile
are asserted never to reach HIGH/CRITICAL, and a single dangerous field added to such
a pod is asserted still to be flagged — so precision work cannot quietly blunt
detection (`tests/test_precision.py`).

## Deliberate limitations

Stated here rather than hidden; see `docs/roadmap.md` for the full list.

| Limitation | Status |
|---|---|
| No Windows container coverage | Deliberate non-goal — no testable target on this host, different detection substrate |
| RPM images report package inventory as *unavailable* | Honest failure, tested; RPM DB parsing not implemented |
| Package delta says *what* changed, not *which CVEs* it fixes | Deliberate — CVE correlation needs a dated vulnerability database |
| Falco rules are schema-validated, not engine-executed | No `falco` binary available |
| CE-003 / CE-008 have no Falco rule | Documented gap by design (not observable as runtime events) |
| Admission precision against a second corpus | Open work |
