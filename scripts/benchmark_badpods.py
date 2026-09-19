#!/usr/bin/env python3
"""Benchmark admission-review against the BishopFox BadPods corpus.

BadPods (https://github.com/BishopFox/badPods) is the de-facto reference set of
deliberately dangerous Kubernetes manifests: 8 "levels" of permission, each
expressed as 8 workload kinds x 2 variants. It is an adversarial recall test —
the question is not "does the tool look good" but "which dangerous pods does it
miss, and are those misses defensible".

Usage:
    benchmark_badpods.py /path/to/badPods [--json out.json] [--markdown out.md]

Outputs a per-level detection matrix with the exact checks that fired, and
lists every miss by name so the gap is visible rather than averaged away.
"""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from escape_corpus.admission_review import AdmissionReviewer  # noqa: E402

WORKLOAD_KINDS = {"Pod", "Deployment", "DaemonSet", "StatefulSet", "Job", "CronJob",
                  "ReplicaSet", "ReplicationController"}


def to_pod_spec(doc: dict) -> dict:
    """Normalise any workload kind into a Pod-shaped dict.

    A Pod carries the container spec directly; every other kind nests it under
    spec.template.spec (CronJob one level deeper, under spec.jobTemplate).
    """
    kind = doc.get("kind", "Pod")
    spec = doc.get("spec", {})
    meta = doc.get("metadata", {}) or {}
    if kind == "Pod":
        pod_spec = spec
    elif kind == "CronJob":
        pod_spec = spec.get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec", {})
    else:
        pod_spec = spec.get("template", {}).get("spec", {})
    return {"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": meta.get("name", "unnamed"),
                         "namespace": meta.get("namespace", "default")},
            "spec": pod_spec}


def load_yaml(path: Path):
    import yaml
    docs = [d for d in yaml.safe_load_all(path.read_text()) if d]
    return [d for d in docs if d.get("kind") in WORKLOAD_KINDS]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("badpods", type=Path, help="path to a BadPods checkout")
    ap.add_argument("--json", type=Path)
    ap.add_argument("--markdown", type=Path)
    args = ap.parse_args()

    manifests = sorted(args.badpods.glob("manifests/*/*/*.yaml"))
    if not manifests:
        print(f"error: no manifests under {args.badpods}/manifests/*/*/*.yaml", file=sys.stderr)
        return 2

    by_level = defaultdict(lambda: {"total": 0, "flagged": 0, "misses": [],
                                    "checks": defaultdict(int), "scores": []})
    results = []

    for path in manifests:
        level = path.relative_to(args.badpods / "manifests").parts[0]
        for doc in load_yaml(path):
            reviewer = AdmissionReviewer()
            pod = to_pod_spec(doc)
            reviewer.review_pod(pod)
            report = reviewer.generate_report(pod, [])
            flagged = report.risk_level in ("CRITICAL", "HIGH")
            bucket = by_level[level]
            bucket["total"] += 1
            bucket["scores"].append(report.risk_score)
            if flagged:
                bucket["flagged"] += 1
            else:
                bucket["misses"].append(f"{path.parent.name}/{path.name}:{doc.get('kind')}")
            for f in report.findings:
                bucket["checks"][f.check] += 1
            results.append({"level": level, "kind": doc.get("kind"), "file": str(path),
                            "risk_level": report.risk_level, "risk_score": report.risk_score,
                            "findings": [f.check for f in report.findings]})

    # --- report ---
    lines = ["# BadPods benchmark — admission-review", "",
             f"Corpus: {len(manifests)} manifests, {sum(v['total'] for v in by_level.values())} workload objects",
             "",
             "A manifest counts as *flagged* when the report lands at HIGH or CRITICAL.",
             "",
             "| BadPods level | objects | flagged | recall | median score |",
             "|---|---|---|---|---|"]

    order = ["nothing-allowed", "hostipc", "hostnetwork", "hostpath", "hostpid",
             "priv", "priv-and-hostpid", "everything-allowed"]
    total = flagged_total = 0
    for level in order + [lvl for lvl in sorted(by_level) if lvl not in order]:
        if level not in by_level:
            continue
        b = by_level[level]
        scores = sorted(b["scores"])
        median = scores[len(scores) // 2] if scores else 0
        recall = 100.0 * b["flagged"] / b["total"] if b["total"] else 0.0
        total += b["total"]
        flagged_total += b["flagged"]
        lines.append(f"| {level} | {b['total']} | {b['flagged']} | {recall:.0f}% | {median} |")

    lines += ["", f"**Overall: {flagged_total}/{total} flagged ({100.0*flagged_total/total:.1f}%)**", ""]

    misses = [(lvl, m) for lvl, b in by_level.items() for m in b["misses"]]
    lines += ["## Misses (not flagged HIGH/CRITICAL)", ""]
    if misses:
        for lvl, m in misses:
            lines.append(f"- `{lvl}` — {m}")
    else:
        lines.append("None.")

    lines += ["", "## Checks that fired (by level)", ""]
    for level in order:
        if level not in by_level:
            continue
        b = by_level[level]
        top = sorted(b["checks"].items(), key=lambda kv: -kv[1])[:8]
        lines.append(f"- **{level}**: " + ", ".join(f"`{c}` ({n})" for c, n in top))

    report_md = "\n".join(lines) + "\n"
    print(report_md)

    if args.markdown:
        args.markdown.write_text(report_md)
        print(f"[+] markdown written to {args.markdown}")
    if args.json:
        args.json.write_text(json.dumps(
            {"totals": {"objects": total, "flagged": flagged_total},
             "by_level": {k: {"total": v["total"], "flagged": v["flagged"],
                              "checks": dict(v["checks"]), "misses": v["misses"]}
                          for k, v in by_level.items()},
             "results": results}, indent=2))
        print(f"[+] json written to {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
