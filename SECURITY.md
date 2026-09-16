# Security Policy

## Supported scope

This repository is a **research corpus and defensive tooling kit**. The tools
in `escape_corpus/` analyze your own infrastructure: image deltas, runtime
drift baselines, and pod admission reviews. They are read-only against their
targets (they never modify containers, images, or clusters).

## What this is NOT

- Not an exploit kit. Playbooks contain PoC *sketches* — mechanics-level
  fragments — not weaponized one-click escapes.
- Not a substitute for your own security assessment. Findings are risk
  indicators, not proofs of compromise.

## Reporting vulnerabilities

If you find a vulnerability in this repository's tooling (not in the
techniques it documents), open an issue with:

1. Affected tool and version
2. Steps to reproduce
3. Impact

Technique-level gaps (missing detection coverage, outdated runc/CVE data) are
also welcome as issues labeled `taxonomy`.

## Safety rules for using the lab

From `corpus/lab/LAB-SETUP.md` — these are non-negotiable:

1. Never run escape PoCs against production or shared infrastructure
2. Keep lab VMs off networks with real workloads
3. Snapshot the VM before destructive tests
4. Only pull images you trust into the lab
5. Log all lab activities for audit
