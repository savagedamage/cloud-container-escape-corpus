#!/usr/bin/env python3
"""Assemble the MkDocs input tree from the canonical corpus files.

The corpus keeps one copy of every artifact (README, playbooks, rules, benchmark
output). A docs site that duplicates that prose would rot immediately, so this
script COPIES the canonical files into docs/ at build time and rewrites the
in-repo relative links to their site paths.

Usage:
    python3 scripts/build_docs.py          # assemble docs/
    mkdocs serve / mkdocs build            # after assembling
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"

# (source relative to repo root, destination name in docs/)
PAGES = [
    ("README.md", "index.md"),
    ("corpus/INDEX.md", "corpus-index.md"),
    ("corpus/taxonomy/container-escape-taxonomy.md", "taxonomy.md"),
    ("corpus/side-channels/side-channel-inventory.md", "side-channels.md"),
    ("corpus/benchmarks/badpods-admission-review.md", "benchmark-badpods.md"),
    ("corpus/lab/LAB-SETUP.md", "lab-setup.md"),
    ("docs/roadmap.md", "roadmap.md"),
    ("VERIFICATION.md", "verification.md"),
    ("SECURITY.md", "security.md"),
    ("CONTRIBUTING.md", "contributing.md"),
    ("CHANGELOG.md", "changelog.md"),
]

MD_LINK = re.compile(r"\]\(([^)]+\.md)(#[^)]*)?\)")
ANY_LINK = re.compile(r"\]\(([^)#\s]+)(#[^)]*)?\)")
REPO_BLOB = "https://github.com/savagedamage/cloud-container-escape-corpus/blob/main"
REPO_TREE = "https://github.com/savagedamage/cloud-container-escape-corpus/tree/main"


def generated_sources() -> list[tuple[Path, str]]:
    """All (source, dest) pairs, including every technique playbook."""
    out = []
    for src_rel, dest in PAGES:
        src = ROOT / src_rel
        if src.exists():
            out.append((src, dest))
    for playbook in sorted((ROOT / "corpus" / "techniques").glob("*.md")):
        out.append((playbook, f"techniques/{playbook.name}"))
    return out


def build_link_map(pairs) -> dict:
    """basename -> site-relative path, for rewriting inter-doc links."""
    return {src.name: dest for src, dest in pairs}


def rewrite_links(text: str, link_map: dict) -> str:
    """Point in-repo links at their site page or their GitHub URL.

    Two classes of link exist in the canonical markdown:
    - other documents  -> rewritten to the generated site page (link_map)
    - data/code files  -> MkDocs would warn (they are not pages), so they point
      at the repo, where the file actually renders/downloads
    """
    def repl(match: re.Match) -> str:
        target, anchor = match.group(1), match.group(2) or ""
        name = target.split("/")[-1]
        if name in link_map:
            return f"]({link_map[name]}{anchor})"
        return match.group(0)

    return MD_LINK.sub(repl, text)


def rewrite_data_links(text: str, src: Path) -> str:
    """Send links to non-document files to GitHub instead of a dead site link."""
    def repl(match: re.Match) -> str:
        target, anchor = match.group(1), match.group(2) or ""
        if "://" in target or target.startswith(("mailto:", "#")):
            return match.group(0)
        resolved = (src.parent / target).resolve()
        try:
            rel = resolved.relative_to(ROOT)
        except ValueError:
            return match.group(0)          # outside the repo: leave alone
        if resolved.is_dir():
            return f"]({REPO_TREE}/{rel}/{anchor})"
        if resolved.is_file():
            return f"]({REPO_BLOB}/{rel}{anchor})"
        return match.group(0)

    return ANY_LINK.sub(repl, text)


def main() -> int:
    pairs = generated_sources()
    if not pairs:
        print("error: no sources found", file=sys.stderr)
        return 2

    link_map = build_link_map(pairs)
    DOCS.mkdir(exist_ok=True)
    for src, dest in pairs:
        target = DOCS / dest
        target.parent.mkdir(parents=True, exist_ok=True)
        text = src.read_text()
        if dest != "roadmap.md":  # roadmap lives in docs/ already
            text = rewrite_links(text, link_map)
            text = rewrite_data_links(text, src)
        target.write_text(text)

    print(f"[+] assembled {len(pairs)} pages into {DOCS}")
    for src, dest in pairs:
        print(f"    {src.relative_to(ROOT)} -> docs/{dest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
