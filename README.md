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
| **Taxonomy** | 10 container escape techniques, risk-scored, MITRE-mapped | [corpus/taxonomy/](corpus/taxonomy/) + `taxonomy.json` (machine) |
| **Playbooks** | Per-technique: prerequisites, attack path, PoC sketch, detection, mitigation | [corpus/techniques/](corpus/techniques/) |
| **Detection rules** | 11 Sigma + 8 Falco rules, indexed to techniques | [corpus/detection/](corpus/detection/) |
| **Side-channels** | /proc, /sys, cgroup v2, namespace, seccomp-notch leakage map | [corpus/side-channels/](corpus/side-channels/) |
| **Lab** | kind cluster setup, vulnerable pod matrix, validation plan | [corpus/lab/](corpus/lab/) |
| **Tools** | image-diff, runtime-baseline, admission-review | pip-installable package |
| **Schemas** | JSON Schemas for taxonomy and every tool output | [schemas/](schemas/) |

The full map for humans: [corpus/INDEX.md](corpus/INDEX.md). For machines:
[corpus/index.yaml](corpus/index.yaml) and
[corpus/taxonomy/taxonomy.json](corpus/taxonomy/taxonomy.json).

## Install

```bash
pip install .            # or: pip install .[dev] for tests + schema validation
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

## Verification status

Unit suite (6/6): `python -m pytest tests/`

Live-verified (kind v1.37.0, containerd 2.3.4, docker 29.8.0):

- `image-diff`: `busybox:1.35→1.36` = LOW(5); `nginx:1.23→1.24` = MEDIUM(35),
  `/etc/shadow` + User change flagged
- `runtime-baseline`: baseline→verify clean; SYS_PTRACE cross-verify = CRITICAL
  (caps + all 8 namespaces); monitor mode clean with rolling hash chain
- `admission-review`: live escape pod = CRITICAL/725, secure pod = MEDIUM/20 —
  matches dry-run fixture scores exactly

## Repository layout

```
escape_corpus/        # pip-installable Python package (3 tools + unified CLI)
corpus/
  taxonomy/           # human taxonomy + taxonomy.json (machine)
  techniques/         # 10 per-technique playbooks (CE-001 … CE-010)
  detection/          # 11 Sigma + 8 Falco rules + rule index
  side-channels/      # /proc /sys cgroup ns seccomp leakage inventory
  lab/                # LAB-SETUP.md + vulnerable pod manifests
  INDEX.md            # human master index
  index.yaml          # machine master index
schemas/              # JSON Schemas (draft 2020-12) for all structured output
tests/                # unit tests + pod fixtures + example policies
```

## Usage policy

All corpus material and tooling is for authorized security research and defense
of your own infrastructure. Escape PoCs belong in the isolated lab
([corpus/lab/LAB-SETUP.md](corpus/lab/LAB-SETUP.md)) — never production, never
shared infrastructure. See [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
