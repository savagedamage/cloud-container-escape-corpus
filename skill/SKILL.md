---
name: container-escape-corpus
description: Use when triaging container/cloud escape risk, comparing OCI image tags, baselineing a running container for drift, or reviewing a pod spec before admission — and when answering "what is technique X / which rules detect it". Ships a taxonomy (CE-001…CE-012), a side-channel inventory (SC-001…SC-010), Sigma+Falco rules, and four analysis tools, all readable as JSON/YAML for machine use.
---

# Container / cloud escape corpus

A corpus of container (and now cloud) escape techniques plus the tooling to apply
them. Everything exists twice on purpose: a human playbook (markdown) and a
machine form (JSON/YAML with a JSON Schema), so the same facts serve a reader and
an agent.

## When to use this

- Comparing two image tags for a risk-weighted delta (`image-diff`)
- Deciding whether a running container has drifted from its baseline (`runtime-baseline`)
- Reviewing a pod/Deployment manifest against security checks before it ships (`admission-review`)
- Looking up a technique, its prerequisites, and the rules that detect it
- Answering "how do I detect container escape X" with a concrete Sigma/Falco rule

## Fast paths

```bash
# Browse the corpus (no cluster, no network)
escape-corpus techniques                       # all CE-### entries
escape-corpus techniques --id CE-001 -v        # full playbook path + metadata
escape-corpus side-channels --id SC-001        # /proc, /sys, cgroup, seccomp, ...
escape-corpus rules --technique CE-007         # rules mapped to a technique
escape-corpus validate                         # consistency gate; run before committing

# Analyse (increasing blast radius / requirements)
admission-review --pod pod.yaml                # pure analysis, no cluster
runtime-baseline baseline --container c1 -o b.json && \
runtime-baseline verify --container c1 --baseline b.json   # reads /proc via runtime exec
escape-corpus image-diff nginx:1.23 nginx:1.24 # PULLS from a registry
```

MCP server (for agent-to-agent use): `escape-corpus-mcp`, or
`pip install 'escape-corpus[mcp]'`. Tools: `list_techniques`, `get_technique`,
`list_side_channels`, `list_detection_rules`, `validate_corpus`, `review_pod`,
`diff_images`, `baseline_snapshot`; resources: `corpus://taxonomy`,
`corpus://side-channels`, `corpus://index`, `corpus://detection-index`.

## Layout

| Path | What it is |
|---|---|
| `corpus/taxonomy/taxonomy.json` | machine taxonomy; `guide` points at the playbook |
| `corpus/techniques/CE-*.md` | one playbook per technique |
| `corpus/side-channels/side-channels.json` | leakage surfaces + mitigations |
| `corpus/detection/{sigma,falco}/` | detection rules; `index.yaml` maps rule → technique |
| `corpus/benchmarks/` | measured results (BadPods recall, sample image diffs) |
| `schemas/*.schema.json` | JSON Schema for every machine-readable artifact |
| `escape_corpus/corpus_data.py` | single source of truth for paths/loading |
| `scripts/verify.sh` | reproduces every verification claim (`--live` for network/docker) |

## Rules this repo enforces (learned the hard way)

1. **Coverage claims must be measured.** If a technique has no lab fixture or no
   rule, the coverage tables show an em dash — never invent one. `escape-corpus
   validate` cross-checks techniques ↔ rules ↔ fixtures.
2. **Falco priorities are Falco's vocabulary**: `EMERGENCY|ALERT|CRITICAL|ERROR|
   WARNING|NOTICE|INFORMATIONAL|DEBUG`. `HIGH` is invalid and silently wrong.
   Sigma severity (`level: high`) is a different field — do not copy it over.
3. **Sigma ATT&CK tags must be real**: technique tags are `attack.t####`
   (optionally `.NNN`), tactic tags are hyphenated (`attack.privilege-escalation`,
   `attack.defense-evasion`). `attack.escape` does not exist; `attack.privilege_escalation`
   (underscore) is rejected by `sigma check`. Always run `sigma check` after editing rules.
4. **Path matching must be component-wise and most-specific-first.** `"/etc" in
   path` also matches `/etcfoo`, and checking `/etc` before `/etc/kubernetes`
   reports the wrong (less specific) finding. Use the boundary-aware matcher.
5. **Mount detection keys on the fstype field, not the source.** A host `/proc`
   bind-mounted elsewhere appears as `proc /host/proc proc`, so `source == "proc"`
   never fires — compare `parts[2]` and exclude the container's own `/proc`.
6. **`nargs="*"` positionals plus interspersed flags differ across Python
   versions.** `parse_args()` rejects `cmd --flag file` on ≤3.12 with
   "unrecognized arguments"; use `parse_intermixed_args()` and keep a regression
   test that runs the CLI in that argument order.
7. **Never let `tarfile`'s `data` filter touch an image layer** when the analysis
   is *about* those signals: it strips setuid bits, security xattrs and absolute
   symlinks, i.e. exactly what `image-diff` measures.
8. **Hardlinks are not content changes.** Compare by link target or a hardlink-heavy
   image reports hundreds of phantom "modified" files.
9. **Diff the packages, not just the files.** `image-diff` reports dpkg/apk
   `added/removed/upgraded`; RPM images report *unavailable* rather than an empty
   delta, because a CentOS image must not look clean.
10. **Evidence or it didn't happen.** Add a test that fails before the fix, and
    run it — this repo's bugs (socket false-negative, pod-level securityContext
    inheritance, stale hash-chain in monitor mode) were all found by tests, not review.

## Verification

```bash
bash scripts/verify.sh          # offline: tests, lint, validate, sigma, schemas
bash scripts/verify.sh --live   # + registry pulls and a real container
```

`VERIFICATION.md` records what was run, when, and with what result. Update it when
claims change — an unevidenced claim is treated as a bug in this repo.
