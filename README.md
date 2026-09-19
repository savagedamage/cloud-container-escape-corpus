# Cloud/Container Escape Corpus

Research corpus, detection content, and analysis tooling for container escape
and cloud runtime security. Built for two audiences: **humans** get playbooks,
and **AI agents** get a validated, machine-readable taxonomy with schemas.

**Unique angle:** container images are treated as *binaries* and runtime state
as *device posture* — the triage/delta/drift pattern from malware analysis,
applied to OCI and Kubernetes.

---

## What's inside

| Component | Content | Readable as |
|---|---|---|
| **Taxonomy** | 12 techniques — 10 container escape + 2 cloud (IMDS, workload identity), risk-scored, MITRE-mapped | [corpus/taxonomy/](corpus/taxonomy/) + `taxonomy.json` (machine) |
| **Playbooks** | Per-technique: prerequisites, attack path, PoC sketch, detection, mitigation | [corpus/techniques/](corpus/techniques/) |
| **Detection rules** | 13 Sigma + 10 Falco rules, indexed to techniques, engine-validated | [corpus/detection/](corpus/detection/) |
| **Side-channels** | 10 leakage surfaces (/proc, /sys, cgroup, ns, seccomp, sockets, layers, caps, time) | [corpus/side-channels/](corpus/side-channels/) + `side-channels.json` (machine) |
| **Lab** | kind cluster setup, 7 vulnerable pod manifests, scripted bring-up + verification | [corpus/lab/](corpus/lab/) |
| **Benchmarks** | Measured results: BadPods recall (128/128), sample image deltas | [corpus/benchmarks/](corpus/benchmarks/) |
| **Tools** | image-diff, runtime-baseline, admission-review | pip-installable package |
| **MCP server** | The corpus as agent-callable tools (8 tools + 4 resources) | `escape-corpus-mcp` |
| **Schemas** | JSON Schemas for taxonomy and every tool output | [schemas/](schemas/) |

The full map for humans: [corpus/INDEX.md](corpus/INDEX.md). For machines:
[corpus/index.yaml](corpus/index.yaml) and
[corpus/taxonomy/taxonomy.json](corpus/taxonomy/taxonomy.json).

## Install

```bash
pip install .            # or: pip install .[dev] for tests, lint and schema validation
pip install '.[mcp]'     # + the MCP server for agent use
escape-corpus --version
```

Requires Python ≥ 3.10. Individual tools need: `crane` or `skopeo` (image-diff),
a container runtime — docker/podman/crictl (runtime-baseline).

## Tools

### `image-diff` — risk-weighted OCI image tag delta

```bash
image-diff nginx:1.23 nginx:1.24 -o diff.json
```

Flattens both images and diffs the merged filesystems: new binaries (ELF,
setuid, file capabilities), changed entrypoint/cmd/User, secret-aware env
deltas, sensitive path changes (`/etc/shadow`, SSH keys, kubeconfigs).
Hardlink-aware (busybox-style applet images don't drown the diff in noise).

Also reports a **package-level delta** (dpkg / apk / rpm `added`/`removed`/`upgraded`),
which names the cause behind a noisy file count — `nginx:1.24→1.25` reads as
"2652 files changed" at file level and "bullseye → bookworm: `libssl1.1 → libssl3`,
120 packages upgraded" at package level. RPM support parses `rpmdb.sqlite` headers
directly (stdlib only, no rpm binding). Only the legacy Berkeley-DB rpmdb in
CentOS 7-era images reports *unavailable*, and it says so rather than looking clean.

**Platform-aware.** `crane` resolves to the *host* architecture by default, so
`--platform linux/arm64` (or `--platform-old`/`--platform-new` to audit a platform
migration) exists because diffing the wrong variant is silently wrong — and
comparing two *different* architectures is not a small delta but a meaningless one,
so that case is called out and scored unless you asked for it.

Fills the gap: dive/trivy scan single images; nothing produces a risk-weighted
delta *between* two tags.

### `runtime-baseline` — runtime drift baseline

```bash
runtime-baseline baseline --container myapp --runtime docker -o baseline.json
runtime-baseline verify   --container myapp --baseline baseline.json
runtime-baseline monitor  --container myapp --baseline baseline.json --interval 30
```

Hash-chained snapshots of capabilities (all five sets + securebits + seccomp +
no_new_privs), cgroup state, all 8 namespace inodes, process identity, and
escape-surface mounts (runtime sockets, host root/proc/sys, read-only rootfs).
DriftDetector flags namespace changes, socket mounts, capability growth, and
hash-chain breaks as CRITICAL.

### `admission-review` — pod dry-run security review

```bash
admission-review --pod pod.yaml --policies policies.yaml -o report.json
```

40+ built-in checks (privileged, hostNetwork/PID/IPC, dangerous capabilities,
runtime sockets, hostPath matrix, hardcoded secrets, `:latest` tags, cgroup
mounts, SYS_ADMIN+/proc combos). Simplified Kyverno/OPA-style custom policies:
`required` / `forbidden` / `equals` / `not_in` with JSONPath-ish paths. Honors
pod-level securityContext propagation semantics.

### `escape-corpus` — unified CLI

```bash
escape-corpus techniques --id CE-001          # browse the knowledge base
escape-corpus rules --technique CE-007 --json # rules covering a technique
escape-corpus validate                        # cross-check corpus consistency
```

### `escape-corpus-mcp` — the corpus as agent tooling

```bash
pip install '.[mcp]' && escape-corpus-mcp     # stdio transport
```

Exposes 8 tools (`list_techniques`, `get_technique`, `list_side_channels`,
`list_detection_rules`, `validate_corpus`, `review_pod`, `diff_images`,
`baseline_snapshot`) and 4 resources (`corpus://taxonomy`, `corpus://side-channels`,
`corpus://index`, `corpus://detection-index`). Read-only with respect to your
infrastructure: `review_pod` is pure analysis, `baseline_snapshot` reads `/proc`
via the runtime, and `diff_images` only pulls from a registry (stated in its
description). The in-repo agent skill lives at [skill/SKILL.md](skill/SKILL.md).

## Verification status

Full record with commands and observed output: **[VERIFICATION.md](VERIFICATION.md)**.
Reproduce with `bash scripts/verify.sh` (offline) or `--live` (registry + docker).

Current state — **11/11 checks passing**:

- **Tests**: 254 passing, **86% coverage** (enforced floor 80% in CI, up from 20%)
- **Lint**: `ruff check` clean
- **Rules**: `sigma check` — 13 rules, 0 errors, 0 issues (engine-validated)
- **Consistency**: `escape-corpus validate` — 12 techniques, 23 rule refs,
  10 side channels, 6 schemas, cross-references consistent
- **Admission benchmark**: BishopFox BadPods **128/128 flagged**, severity gradient
  tracks the permission level (median 125 → 380). Every level lands at CRITICAL
  because even its least-permissive level omits every restricted-profile control —
  the *score* is the discriminating signal, and `tests/test_severity_calibration.py`
  pins the ordering
- **Admission precision**: hardened pods built to the Pod Security Standards
  "restricted" profile are never flagged HIGH/CRITICAL (`tests/test_precision.py`),
  and a single dangerous field on such a pod still is
- **Admission fixtures**: 7/7 lab manifests CRITICAL; escape fixture CRITICAL/695,
  secure fixture MEDIUM/20
- **`image-diff` (live)**: `busybox:1.35→1.36` LOW(5); `nginx:1.23→1.24` MEDIUM(35),
  `/etc/shadow` + User change flagged; `nginx:1.24→1.25` CRITICAL(11035) with a
  120-package upgrade delta; `rockylinux:9-minimal→9` rpm `+38 -15` (dnf, binutils,
  curl-minimal); `--platform linux/arm64` pulls the arm64 variant
- **`runtime-baseline` (live)**: baseline→verify clean; SYS_PTRACE cross-verify =
  CRITICAL (capability bit 19 + all 8 namespace inodes); monitor mode clean with a
  rolling hash chain
- **Docs**: `mkdocs build --strict` from generated sources — 23 pages

The test suite has found the bugs that review did not: host `/proc` bind-mount
detection keyed on the wrong mount field, `/etc/kubernetes` matching the shorter
`/etc` key, unbounded `startswith` path matching, `review_pod` returning
dataclasses that did not survive JSON serialization, a crash on mode-0000 files
(`/etc/shadow-` in every RHEL image), cgroup resource-limit drift never being
compared at all, and a report level that could understate its own worst finding.

## Repository layout

```
escape_corpus/        # pip-installable package (3 tools + CLI + MCP server)
  corpus_data.py      #   single source of truth for corpus paths/loading
  packages.py         #   dpkg/apk inventory + delta
corpus/
  taxonomy/           # human taxonomy + taxonomy.json (machine)
  techniques/         # 12 per-technique playbooks (CE-001 … CE-012)
  detection/          # 13 Sigma + 10 Falco rules + rule index
  side-channels/      # /proc /sys cgroup ns seccomp leakage inventory
  lab/                # LAB-SETUP.md, 7 pod manifests, up.sh + verify.sh
  benchmarks/         # measured results (BadPods, sample image diffs)
  INDEX.md            # human master index
  index.yaml          # machine master index
schemas/              # JSON Schemas (draft 2020-12) for all structured output
scripts/              # verify.sh, benchmark_badpods.py, build_docs.py
skill/                # agent skill for using this corpus
docs/                 # roadmap.md (+ generated site pages, gitignored)
tests/                # 193 tests + pod fixtures + example policies
```

## Usage policy

All corpus material and tooling is for authorized security research and defense
of your own infrastructure. Escape PoCs belong in the isolated lab
([corpus/lab/LAB-SETUP.md](corpus/lab/LAB-SETUP.md)) — never production, never
shared infrastructure. See [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
