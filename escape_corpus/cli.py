#!/usr/bin/env python3
"""
escape-corpus — unified CLI for the Cloud/Container Escape Corpus.

Routes to the three analysis tools and serves the structured knowledge base:

    escape-corpus image-diff <old> <new> [...]     risk-weighted OCI tag delta
    escape-corpus baseline ...                     runtime drift baseline/verify/monitor
    escape-corpus admit --pod <file> [...]         pod admission security review
    escape-corpus techniques [--id CE-001] [--json]   browse the technique taxonomy
    escape-corpus rules [--technique CE-001] [--json] browse detection rules
    escape-corpus schemas                          list output schemas
    escape-corpus validate                         cross-check taxonomy/index/rules/schemas

Every subcommand that emits data supports --json for stable machine output.
"""

import argparse
import json
import sys
from pathlib import Path

from . import __version__

CORPUS_ROOT = Path(__file__).resolve().parent.parent
TAXONOMY_PATH = CORPUS_ROOT / "corpus" / "taxonomy" / "taxonomy.json"
INDEX_PATH = CORPUS_ROOT / "corpus" / "index.yaml"
DETECTION_INDEX_PATH = CORPUS_ROOT / "corpus" / "detection" / "index.yaml"
SCHEMAS_DIR = CORPUS_ROOT / "schemas"


def _delegate(fn, argv):
    """Invoke one of the tool mains with a fresh argv."""
    old = sys.argv
    sys.argv = argv
    try:
        fn()
    finally:
        sys.argv = old


def cmd_image_diff(args):
    from . import image_diff
    argv = ["image-diff", args.old_image, args.new_image]
    if args.output:
        argv += ["-o", args.output]
    if args.verbose:
        argv += ["-v"]
    _delegate(image_diff.main, argv)


def cmd_baseline(args):
    from . import runtime_baseline
    argv = ["runtime-baseline", args.command]
    argv += ["--container", args.container]
    if args.runtime:
        argv += ["--runtime", args.runtime]
    if getattr(args, "baseline", None):
        argv += ["--baseline", args.baseline]
    if getattr(args, "output", None):
        argv += ["--output", args.output]
    if getattr(args, "interval", None):
        argv += ["--interval", str(args.interval)]
    _delegate(runtime_baseline.main, argv)


def cmd_admit(args):
    from . import admission_review
    argv = ["admission-review", "--pod", args.pod]
    if args.policies:
        argv += ["--policies", args.policies]
    if args.output:
        argv += ["--output", args.output]
    if args.json:
        argv += ["--json"]
    _delegate(admission_review.main, argv)


def _load_taxonomy() -> dict:
    with open(TAXONOMY_PATH) as f:
        return json.load(f)


def cmd_techniques(args):
    taxonomy = _load_taxonomy()
    if args.id:
        t = next((x for x in taxonomy["techniques"] if x["id"] == args.id.upper()), None)
        if t is None:
            print(f"Unknown technique id {args.id}. Known: " +
                  ", ".join(x["id"] for x in taxonomy["techniques"]), file=sys.stderr)
            sys.exit(1)
        if args.json:
            print(json.dumps(t, indent=2))
        else:
            print(f"{t['id']} — {t['name']}")
            print(f"  category:    {t['category']}")
            print(f"  mitre:       {', '.join(t['mitre_attack'])}")
            print(f"  risk:        {t['risk']['overall'].upper()}")
            print(f"  prereqs:     {', '.join(t['prerequisites'])}")
            print(f"  guide:       corpus/{t['guide']}")
            print(f"  detections:  {', '.join(t['detection_rule_ids'])}")
            print(f"  summary:     {t['summary']}")
    else:
        if args.json:
            print(json.dumps(taxonomy["techniques"], indent=2))
        else:
            for t in taxonomy["techniques"]:
                print(f"{t['id']:8s} {t['risk']['overall'].upper():10s} {t['name']}")


def _load_yaml(path: Path) -> dict:
    import yaml
    with open(path) as f:
        return yaml.safe_load(f)


def cmd_rules(args):
    dindex = _load_yaml(DETECTION_INDEX_PATH)
    rules = dindex.get("rules", [])
    if args.technique:
        rules = [r for r in rules if args.technique.upper() in r.get("detects", [])]
    if args.json:
        print(json.dumps(rules, indent=2))
    else:
        for r in rules:
            print(f"{r['id']:12s} {r['engine']:7s} {r['title']}")


def cmd_schemas(args):
    schemas = sorted(p.name for p in SCHEMAS_DIR.glob("*.schema.json"))
    for s in schemas:
        print(s)


def cmd_validate(args):
    """Cross-check consistency of the structured corpus files."""
    errors = []
    ids: list = []
    taxonomy: dict = {}

    # 1. taxonomy.json parses and has the expected shape
    try:
        taxonomy = _load_taxonomy()
        ids = [t["id"] for t in taxonomy["techniques"]]
        if len(ids) != len(set(ids)):
            errors.append("taxonomy.json: duplicate technique ids")
        for t in taxonomy["techniques"]:
            guide = CORPUS_ROOT / "corpus" / t["guide"]
            if not guide.exists():
                errors.append(f"{t['id']}: guide file missing: {t['guide']}")
            for rid in t.get("detection_rule_ids", []):
                if rid not in taxonomy.get("detection_rules", {}):
                    errors.append(f"{t['id']}: references unknown rule {rid}")
    except Exception as e:
        errors.append(f"taxonomy.json: {e}")

    # 2. index.yaml parses and cross-references taxonomy
    try:
        index = _load_yaml(INDEX_PATH)
        listed = set(index.get("techniques", []))
        if listed and listed != set(ids):
            errors.append(f"index.yaml technique list mismatch: {sorted(listed ^ set(ids))}")
    except Exception as e:
        errors.append(f"index.yaml: {e}")

    # 3. detection index parses and every rule file exists
    try:
        dindex = _load_yaml(DETECTION_INDEX_PATH)
        for r in dindex.get("rules", []):
            f = CORPUS_ROOT / "corpus" / "detection" / r["file"]
            if not f.exists():
                errors.append(f"rule {r['id']}: file missing: {r['file']}")
    except Exception as e:
        errors.append(f"detection/index.yaml: {e}")

    # 4. schemas are valid JSON
    for s in SCHEMAS_DIR.glob("*.schema.json"):
        try:
            json.loads(s.read_text())
        except Exception as e:
            errors.append(f"schema {s.name}: invalid JSON: {e}")

    # 5. optional: full JSON Schema validation when jsonschema is available
    try:
        import jsonschema  # noqa: F401
        have_jsonschema = True
    except ImportError:
        have_jsonschema = False

    if have_jsonschema:
        import jsonschema
        schema_map = {
            "taxonomy": "taxonomy.schema.json",
        }
        for name, sfile in schema_map.items():
            try:
                jsonschema.validate(taxonomy, json.loads((SCHEMAS_DIR / sfile).read_text()))
            except Exception as e:
                errors.append(f"{name} vs {sfile}: {e}")

    if errors:
        print("VALIDATION FAILED:")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)
    print(f"OK — {len(ids)} techniques, {len(taxonomy.get('detection_rules', {}))} rule refs, "
          f"{len(list(SCHEMAS_DIR.glob('*.schema.json')))} schemas, cross-references consistent"
          + (" (jsonschema deep-check)" if have_jsonschema else " (jsonschema not installed; pip install .[dev])"))


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="escape-corpus",
        description="Cloud/Container Escape Corpus — analysis tools and knowledge base",
    )
    parser.add_argument("--version", action="version", version=f"escape-corpus {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("image-diff", help="Risk-weighted OCI image tag delta")
    p.add_argument("old_image")
    p.add_argument("new_image")
    p.add_argument("-o", "--output")
    p.add_argument("-v", "--verbose", action="store_true")
    p.set_defaults(func=cmd_image_diff)

    p = sub.add_parser("baseline", help="Runtime drift baseline/verify/monitor")
    p.add_argument("command", choices=["baseline", "verify", "monitor"])
    p.add_argument("--container", required=True)
    p.add_argument("--runtime", choices=["docker", "podman", "crictl"])
    p.add_argument("--baseline")
    p.add_argument("--output")
    p.add_argument("--interval", type=int)
    p.set_defaults(func=cmd_baseline)

    p = sub.add_parser("admit", help="Pod admission security review")
    p.add_argument("--pod", required=True)
    p.add_argument("--policies")
    p.add_argument("--output")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_admit)

    p = sub.add_parser("techniques", help="Browse the technique taxonomy")
    p.add_argument("--id")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_techniques)

    p = sub.add_parser("rules", help="Browse detection rules")
    p.add_argument("--technique")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_rules)

    p = sub.add_parser("schemas", help="List output schemas")
    p.set_defaults(func=cmd_schemas)

    p = sub.add_parser("validate", help="Cross-check corpus consistency")
    p.set_defaults(func=cmd_validate)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
