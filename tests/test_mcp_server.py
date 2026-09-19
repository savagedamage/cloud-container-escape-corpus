"""Tests for the MCP server (optional extra).

Skipped when fastmcp is not installed, so the core suite stays dependency-light.
The client round-trip is the real proof: it exercises registration, argument
validation, and serialisation, not just the underlying functions.
"""

import asyncio
import json

import pytest

pytest.importorskip("fastmcp", reason="MCP server needs the [mcp] extra")

from escape_corpus import mcp_server as m  # noqa: E402


class TestKnowledgeBaseTools:
    def test_list_techniques_shape(self):
        items = m.list_techniques()
        assert len(items) >= 10
        for item in items:
            assert item["id"].startswith("CE-")
            assert item["risk"] in ("low", "medium", "high", "critical")
            assert item["mitre_attack"]

    def test_get_technique_is_case_insensitive(self):
        assert m.get_technique("ce-007")["id"] == "CE-007"

    def test_get_technique_includes_rules_and_playbook(self):
        t = m.get_technique("CE-001")
        assert t["detection_rules"], "a technique with rules must expose them"
        assert "## Mitigation" in t["playbook_markdown"]
        assert t["playbook_markdown"].startswith("---")   # frontmatter preserved

    def test_get_technique_unknown_id_raises(self):
        with pytest.raises(KeyError, match="unknown technique"):
            m.get_technique("CE-999")

    def test_side_channels_all_and_filtered(self):
        assert len(m.list_side_channels()) >= 10
        assert m.list_side_channels("sc-002")[0]["name"].startswith("Shared /sys")

    def test_side_channel_unknown_raises(self):
        with pytest.raises(ValueError):
            m.list_side_channels("SC-999")

    def test_rules_filter_by_technique_and_engine(self):
        assert {r["engine"] for r in m.list_detection_rules("CE-007")} == {"sigma", "falco"}
        falco = m.list_detection_rules(engine="falco")
        assert falco and all(r["engine"] == "falco" for r in falco)
        assert m.list_detection_rules("CE-999") == []

    def test_validate_corpus_reports_ok(self):
        result = m.validate_corpus()
        assert result["ok"] is True
        assert "OK" in result["output"]


class TestAnalysisTools:
    def test_review_pod_flags_a_dangerous_spec(self):
        pod = """
apiVersion: v1
kind: Pod
metadata: {name: bad, namespace: default}
spec:
  hostPID: true
  containers:
    - name: c
      image: ubuntu:latest
      securityContext:
        privileged: true
"""
        report = m.review_pod(pod)
        assert report["risk_level"] == "CRITICAL"
        checks = {f["check"] for f in report["findings"]}
        assert {"privileged_container", "host_pid"} <= checks

    def test_review_pod_applies_custom_policies(self):
        pod = "apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec: {hostNetwork: true, containers: [{name: c, image: i}]}"
        policy = "forbid-net:\n  kind: forbidden\n  path: spec.hostNetwork\n  severity: HIGH\n"
        report = m.review_pod(pod, policy)
        assert "forbid-net" in {v["check"] for v in report["policy_violations"]}

    def test_review_pod_rejects_invalid_yaml(self):
        with pytest.raises(ValueError, match="not valid YAML"):
            m.review_pod("just: [a, scalar\n")

    def test_review_pod_rejects_non_mapping(self):
        with pytest.raises(ValueError, match="must decode to a mapping"):
            m.review_pod("- a\n- b\n")

    def test_review_pod_rejects_bad_policy_yaml(self):
        pod = "apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec: {containers: [{name: c, image: i}]}"
        with pytest.raises(ValueError, match="policies_yaml"):
            m.review_pod(pod, "broken: [\n")


class TestRegistration:
    def test_all_expected_tools_are_registered(self):
        async def go():
            from fastmcp import Client
            async with Client(m.mcp) as c:
                return {t.name for t in await c.list_tools()}
        names = asyncio.run(go())
        assert {"list_techniques", "get_technique", "list_side_channels",
                "list_detection_rules", "validate_corpus", "review_pod",
                "diff_images", "baseline_snapshot"} <= names

    def test_resources_expose_structured_data(self):
        async def go():
            from fastmcp import Client
            async with Client(m.mcp) as c:
                uris = {str(r.uri) for r in await c.list_resources()}
                tax = await c.read_resource("corpus://taxonomy")
                return uris, tax
        uris, tax = asyncio.run(go())
        assert {"corpus://taxonomy", "corpus://side-channels",
                "corpus://index", "corpus://detection-index"} <= uris
        payload = tax[0].text if isinstance(tax, list) else tax
        doc = json.loads(payload) if isinstance(payload, str) else payload
        assert doc["techniques"], "taxonomy resource must carry the technique list"

    def test_client_round_trip_returns_serialisable_data(self):
        async def go():
            from fastmcp import Client
            async with Client(m.mcp) as c:
                res = await c.call_tool("get_technique", {"technique_id": "CE-001"})
                return res.data
        data = asyncio.run(go())
        assert data["id"] == "CE-001"
        assert isinstance(data["detection_rules"], list)
