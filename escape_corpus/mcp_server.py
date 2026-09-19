"""Read-only MCP server exposing the corpus and the analysis tools.

Why this exists: the corpus was built to be readable by humans *and* agents. The
JSON/YAML layer makes it parseable; this server makes it CALLABLE — an agent can
ask for a technique, get the matching detection rules, dry-run a pod spec, or
diff two image tags without shelling out.

Design constraints:
- Read-only by default. Nothing here mutates a cluster, an image, or a container.
  `diff_images` pulls from a registry and `baseline_snapshot` reads a running
  container's /proc; both are documented as such in their tool descriptions.
- Optional dependency. Install with ``pip install 'escape-corpus[mcp]'``.
- Tools are plain functions, registered explicitly, so they are unit-testable
  without an MCP client.

Run it:
    escape-corpus-mcp                  # stdio transport (default)
    python -m escape_corpus.mcp_server
"""

from __future__ import annotations

import contextlib
import io
from typing import Any, Dict, List, Optional

try:
    from fastmcp import FastMCP
except ImportError as exc:  # pragma: no cover - exercised by packaging, not logic
    raise ImportError(
        "the MCP server requires the optional extra: pip install 'escape-corpus[mcp]'"
    ) from exc

from . import cli
from . import corpus_data as cd
from .admission_review import AdmissionReviewer

mcp = FastMCP(
    "escape-corpus",
    instructions=(
        "Container escape research corpus. Browse techniques (CE-###), side-channel "
        "surfaces (SC-###), and detection rules (SIGMA-###/FALCO-###); dry-run a pod "
        "spec for security findings; diff two OCI image tags for a risk-weighted delta. "
        "All tools are read-only with respect to your infrastructure."
    ),
)


# --------------------------------------------------------------------------- #
# knowledge base
# --------------------------------------------------------------------------- #

def list_techniques() -> List[Dict[str, Any]]:
    """List every escape technique with id, name, category, MITRE mapping and risk."""
    return [
        {
            "id": t["id"],
            "name": t["name"],
            "category": t["category"],
            "risk": t["risk"]["overall"],
            "mitre_attack": t["mitre_attack"],
        }
        for t in cd.techniques()
    ]


def get_technique(technique_id: str) -> Dict[str, Any]:
    """Full detail for one technique, including its human playbook in markdown.

    technique_id accepts any case (e.g. "ce-007").
    """
    t = cd.technique_by_id(technique_id)
    return {
        **t,
        "detection_rules": cd.rules_for_technique(t["id"]),
        "playbook_markdown": cd.read_guide(t),
    }


def list_side_channels(surface_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """List the information-leakage surfaces (/proc, /sys, cgroup, seccomp, ...)."""
    surfaces = cd.load_side_channels()["surfaces"]
    if surface_id:
        wanted = surface_id.strip().upper()
        surfaces = [s for s in surfaces if s["id"] == wanted]
        if not surfaces:
            raise ValueError(f"unknown surface id {surface_id!r}")
    return surfaces


def list_detection_rules(technique_id: Optional[str] = None, engine: Optional[str] = None) -> List[Dict[str, Any]]:
    """List detection rules, optionally filtered by technique id and/or engine.

    engine is "sigma" or "falco".
    """
    rules = cd.load_detection_index().get("rules", [])
    if technique_id:
        wanted = technique_id.strip().upper()
        rules = [r for r in rules if wanted in r.get("detects", [])]
    if engine:
        wanted_engine = engine.strip().lower()
        rules = [r for r in rules if r.get("engine") == wanted_engine]
    return rules


def validate_corpus() -> Dict[str, Any]:
    """Cross-check the corpus for internal consistency (taxonomy, index, rules, schemas)."""
    buf = io.StringIO()
    ok = True
    with contextlib.redirect_stdout(buf):
        try:
            cli.cmd_validate(None)
        except SystemExit as exc:
            ok = exc.code == 0
    return {"ok": ok, "output": buf.getvalue().strip()}


# --------------------------------------------------------------------------- #
# analysis
# --------------------------------------------------------------------------- #

def review_pod(pod_yaml: str, policies_yaml: Optional[str] = None) -> Dict[str, Any]:
    """Dry-run a Kubernetes pod spec and return security findings + a risk score.

    Read-only: nothing is submitted to a cluster. pod_yaml is the manifest text;
    policies_yaml is an optional policy document in the corpus's simplified
    Kyverno/OPA format.
    """
    import yaml
    try:
        pod = yaml.safe_load(pod_yaml)
    except yaml.YAMLError as exc:
        raise ValueError(f"pod_yaml is not valid YAML: {exc}") from exc
    if not isinstance(pod, dict):
        raise ValueError("pod_yaml must decode to a mapping")

    reviewer = AdmissionReviewer()
    reviewer.review_pod(pod)
    policies: Dict[str, Any] = {}
    if policies_yaml:
        try:
            policies = yaml.safe_load(policies_yaml) or {}
        except yaml.YAMLError as exc:
            raise ValueError(f"policies_yaml is not valid YAML: {exc}") from exc
    violations = reviewer.review_against_policies(pod, policies) if policies else []
    report = reviewer.generate_report(pod, violations)
    # asdict() recurses into the nested Finding dataclasses; report.__dict__ would
    # leave them as objects that do not survive JSON serialisation.
    import dataclasses
    return dataclasses.asdict(report)


def diff_images(old_image: str, new_image: str) -> Dict[str, Any]:
    """Risk-weighted delta between two OCI image tags.

    NOTE: this PULLS both images from their registry (no local infra is modified).
    Requires `crane` or `skopeo` on PATH.
    """
    import json
    import sys

    from . import image_diff

    argv = ["image-diff", old_image, new_image]
    buf = io.StringIO()
    old_argv = sys.argv
    sys.argv = argv
    try:
        with contextlib.redirect_stdout(buf):
            image_diff.main()
    finally:
        sys.argv = old_argv

    text = buf.getvalue()
    start = text.find("{")
    if start == -1:
        raise RuntimeError(f"image diff produced no JSON result:\n{text}")
    return json.loads(text[start:])


def baseline_snapshot(container: str, runtime: str = "docker") -> Dict[str, Any]:
    """Take a runtime drift snapshot of a running container (read-only).

    Reads capabilities, cgroups, namespaces, process identity and escape-surface
    mounts via the container runtime's exec facility. runtime is
    "docker" | "podman" | "crictl". Nothing is modified.
    """
    import dataclasses

    from .runtime_baseline import RuntimeBaseline

    rb = RuntimeBaseline(
        container,
        use_docker=runtime == "docker",
        use_podman=runtime == "podman",
        use_crictl=runtime == "crictl",
    )
    return dataclasses.asdict(rb.capture())


# --------------------------------------------------------------------------- #
# registration
# --------------------------------------------------------------------------- #

for _fn in (list_techniques, get_technique, list_side_channels, list_detection_rules,
            validate_corpus, review_pod, diff_images, baseline_snapshot):
    mcp.tool(_fn)


@mcp.resource("corpus://taxonomy")
def resource_taxonomy() -> str:
    """The machine-readable technique taxonomy (JSON)."""
    import json
    return json.dumps(cd.load_taxonomy(), indent=2)


@mcp.resource("corpus://side-channels")
def resource_side_channels() -> str:
    """The machine-readable side-channel inventory (JSON)."""
    import json
    return json.dumps(cd.load_side_channels(), indent=2)


@mcp.resource("corpus://index")
def resource_index() -> str:
    """The corpus entry-point index (YAML)."""
    return cd.paths().index.read_text()


@mcp.resource("corpus://detection-index")
def resource_detection_index() -> str:
    """Rule → technique mapping for every detection rule (YAML)."""
    return cd.paths().detection_index.read_text()


def main() -> None:
    """Console entry point."""
    mcp.run()


if __name__ == "__main__":  # pragma: no cover
    main()
