"""Locate and load the structured corpus.

Single source of truth for where the corpus data lives, shared by the CLI and
the MCP server. Resolution order:

1. Source checkout / editable install — the repo root above this package.
2. Installed package — data files shipped to ``<sys.prefix>/share/escape-corpus``
   by ``[tool.setuptools.data-files]`` in pyproject.toml.
"""

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class CorpusPaths:
    root: Path

    @property
    def taxonomy(self) -> Path:
        return self.root / "corpus" / "taxonomy" / "taxonomy.json"

    @property
    def taxonomy_md(self) -> Path:
        return self.root / "corpus" / "taxonomy" / "container-escape-taxonomy.md"

    @property
    def side_channels(self) -> Path:
        return self.root / "corpus" / "side-channels" / "side-channels.json"

    @property
    def index(self) -> Path:
        return self.root / "corpus" / "index.yaml"

    @property
    def detection_index(self) -> Path:
        return self.root / "corpus" / "detection" / "index.yaml"

    @property
    def techniques_dir(self) -> Path:
        return self.root / "corpus" / "techniques"

    @property
    def schemas_dir(self) -> Path:
        return self.root / "schemas"

    def technique_guide(self, guide: str) -> Path:
        """Resolve a taxonomy `guide` value (relative to corpus/) to a path."""
        return self.root / "corpus" / guide

    def schema(self, name: str) -> Path:
        return self.schemas_dir / name


def find_corpus_root() -> Path:
    """Return the directory containing ``corpus/`` and ``schemas/``."""
    dev = Path(__file__).resolve().parent.parent
    if (dev / "corpus" / "taxonomy" / "taxonomy.json").exists():
        return dev
    installed = Path(sys.prefix) / "share" / "escape-corpus"
    if (installed / "corpus" / "taxonomy" / "taxonomy.json").exists():
        return installed
    raise FileNotFoundError(
        "corpus data files not found — install with `pip install .` or run from the repo root"
    )


def paths() -> CorpusPaths:
    return CorpusPaths(find_corpus_root())


def load_json(path: Path) -> Dict[str, Any]:
    with open(path) as f:
        return json.load(f)


def load_yaml(path: Path) -> Dict[str, Any]:
    import yaml
    with open(path) as f:
        return yaml.safe_load(f)


def load_taxonomy(path: Optional[Path] = None) -> Dict[str, Any]:
    return load_json(path or paths().taxonomy)


def load_side_channels(path: Optional[Path] = None) -> Dict[str, Any]:
    return load_json(path or paths().side_channels)


def load_detection_index(path: Optional[Path] = None) -> Dict[str, Any]:
    return load_yaml(path or paths().detection_index)


def techniques(taxonomy: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    return (taxonomy or load_taxonomy())["techniques"]


def technique_by_id(technique_id: str, taxonomy: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Case-insensitive lookup; raises KeyError with the known ids listed."""
    wanted = technique_id.strip().upper()
    for t in techniques(taxonomy):
        if t["id"] == wanted:
            return t
    known = ", ".join(t["id"] for t in techniques(taxonomy))
    raise KeyError(f"unknown technique {technique_id!r}; known: {known}")


def rules_for_technique(technique_id: str, detection_index: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    wanted = technique_id.strip().upper()
    index = detection_index or load_detection_index()
    return [r for r in index.get("rules", []) if wanted in r.get("detects", [])]


def read_guide(technique: Dict[str, Any]) -> str:
    """Return the playbook markdown for a technique entry."""
    return paths().technique_guide(technique["guide"]).read_text()
