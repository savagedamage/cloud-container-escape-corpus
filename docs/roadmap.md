# Roadmap and deliberate non-goals

This file records what the corpus does **not** do, and why. A corpus that claims
total coverage without stating its boundaries is less useful than one that names
them — the gaps below are decisions, not oversights.

## Deliberate non-goals

### Windows containers

Out of scope for v1.x, for three concrete reasons:

1. **No testable target on the development host.** This corpus is developed and
   verified on Linux (docker/containerd + kind). A Windows container escape needs
   a Windows host with `containerd` in Windows-container mode, or a Windows VM
   under Hyper-V. Techniques such as token theft from `wininit`/`services`, named
   pipe abuse, and `\\.\pipe\docker_engine` access cannot be honestly verified
   here, and unverified content violates this corpus's evidence rule.
2. **Different detection substrate.** The Sigma/Falco rules here assume Linux
   auditd/Sysmon-over-containers semantics. Windows container escape detection
   needs Sysmon/ETW coverage of host processes plus container-aware Windows event
   channels — a separate rule set, not a port of these.
3. **Different escape surface.** The interesting Windows-container primitives are
   not cgroup/namespace/`/proc` based. A Windows section would share almost no
   machinery with CE-001…CE-012, so it would be a bolt-on appendix rather than an
   extension of the taxonomy.

What it would take to add properly: a Windows host with containers enabled, a
matching lab bring-up script, and Sysmon/ETW rule validation — i.e. a parallel
lab, not a new markdown file. Tracked as an open item, not silently missing.

### Weaponised exploit tooling

`SECURITY.md` states the rule: playbooks stay at the mechanics level (what the
primitive *is*, what it requires, how to detect it). No turnkey exploit scripts,
no one-liners that escape a container without adaptation. This is a permanent
non-goal, not a backlog item.

### Live cluster mutation

The tools here analyse; they do not mutate. `admission-review` dry-runs a
manifest, `image-diff` pulls and flattens images, `runtime-baseline` reads
`/proc` and cgroup state. Nothing applies, patches, or deletes cluster state.

## Known limitations (stated, not hidden)

| Limitation | Impact | Status |
|---|---|---|
| Legacy Berkeley-DB rpmdb (RPM < 4.16, e.g. CentOS 7) is not parsed | `image-diff` reports the inventory as *unavailable* for those images rather than an empty delta | Accepted — needs a Berkeley DB binding. `rpmdb.sqlite` (RHEL 8+) IS parsed, verified 118/118 against rockylinux:9-minimal |
| Package delta reports *what* changed, not *whether it fixes a CVE* | Correlating `libssl3 → 3.0.13` with a CVE requires a vulnerability database (OSV/Grype data) | Open — deliberately not faked; see below |
| Falco rules are schema-validated, not engine-executed | CI cannot run `falco` (no binary), so a rule that parses but never fires would not be caught | Accepted — Sigma rules ARE engine-validated via `sigma check`; Falco conditions use the same field vocabulary as the validated set |
| CE-003 and CE-008 have no Falco rule | RBAC and kernel-syscall exploitation are not observable as container runtime events | Documented in the detection coverage table as a gap by design |
| No CI job applies the lab manifests to a cluster | CI analyses every manifest with `admission-review` but never `kubectl apply`s it, so an apply-time schema problem would not be caught | Open — needs a kind-based CI job; the equivalent is a documented local run (`corpus/lab/up.sh --yes` then `corpus/lab/verify.sh`) |
| Windows containers | No coverage at all | Open — see above |

### Why no CVE correlation in the package delta

Adding "3 CVEs fixed" to an image diff would require shipping or downloading a
vulnerability database. Doing that badly is worse than not doing it: a stale or
partial CVE mapping produces confident-but-wrong risk numbers. The current
output is deliberately factual — *these packages changed, in this direction* —
which an operator can feed into their existing scanner. If CVE correlation is
added later it should consume OSV data with a stated freshness timestamp, not a
bundled snapshot of unknown age.

## Planned work

- **Admission benchmark against Kubernetes Goat**: a second, differently-authored
  adversarial corpus to complement the BadPods recall result (BadPods is maximally
  hostile). Precision is now covered by the PSS-restricted compliance corpus in
  `tests/test_precision.py`; a second adversarial corpus would add recall breadth.
- **CE-011/CE-012 cloud techniques**: instance-metadata and workload-identity
  token theft, closing the "Cloud/" half of the repo name.
- **Kind-based CI job**: apply the lab manifests in CI (they are currently only
  analysed, never applied).
- **RPM Berkeley-DB (CentOS 7) inventory**: the last unparsed package database.
