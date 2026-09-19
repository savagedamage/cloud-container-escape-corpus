"""Validation for the Falco rules and the detection index.

The Falco *binary* is not a dependency of this corpus, so structural
correctness is enforced here instead: every rule file must satisfy the
published schema, and the detection index must agree with the files on disk.

Sigma rules are validated for real by `sigma check` (see CI / VERIFICATION.md);
this is the equivalent gate for the Falco half.
"""

import json
from pathlib import Path

import pytest
import yaml

CORPUS = Path(__file__).resolve().parent.parent / "corpus"
FALCO_DIR = CORPUS / "detection" / "falco"
SIGMA_DIR = CORPUS / "detection" / "sigma"
SCHEMA = json.loads((Path(__file__).resolve().parent.parent /
                     "schemas" / "falco-rule.schema.json").read_text())


def falco_files():
    return sorted(FALCO_DIR.glob("*.yaml"))


def load_index():
    return yaml.safe_load((CORPUS / "detection" / "index.yaml").read_text())


class TestFalcoRules:
    def test_at_least_one_rule_file(self):
        assert falco_files(), "no Falco rules found"

    @pytest.mark.parametrize("path", falco_files(), ids=lambda p: p.name)
    def test_schema_valid(self, path):
        jsonschema = pytest.importorskip("jsonschema")
        doc = yaml.safe_load(path.read_text())
        jsonschema.validate(doc, SCHEMA)

    @pytest.mark.parametrize("path", falco_files(), ids=lambda p: p.name)
    def test_rule_names_are_unique_within_a_file(self, path):
        doc = yaml.safe_load(path.read_text())
        names = [r["rule"] for r in doc]
        assert len(names) == len(set(names))

    @pytest.mark.parametrize("path", falco_files(), ids=lambda p: p.name)
    def test_condition_references_falco_fields(self, path):
        """A condition with no evt/fd/proc/container reference is almost
        certainly a transcription error rather than a real filter."""
        doc = yaml.safe_load(path.read_text())
        for rule in doc:
            cond = rule["condition"]
            assert any(token in cond for token in ("evt.", "fd.", "proc.", "container.", "spawned_process")), \
                f"{rule['rule']}: condition looks unfiltered: {cond!r}"

    def test_every_rule_is_indexed(self):
        indexed = {r["file"].split("/")[-1]: r for r in load_index()["rules"] if r["engine"] == "falco"}
        on_disk = {p.name for p in falco_files()}
        assert on_disk == set(indexed), f"index/disk mismatch: {on_disk ^ set(indexed)}"

    def test_index_priority_matches_rule(self):
        """The index carries corpus-severity levels (CRITICAL/HIGH/MEDIUM/LOW);
        Falco's own vocabulary is different, so compare through a mapping."""
        level_map = {
            "CRITICAL": {"CRITICAL", "ALERT", "EMERGENCY"},
            "HIGH": {"WARNING", "ERROR"},
            "MEDIUM": {"NOTICE"},
            "LOW": {"INFORMATIONAL", "DEBUG"},
        }
        index = {r["file"].split("/")[-1]: r for r in load_index()["rules"] if r["engine"] == "falco"}
        for path in falco_files():
            entry = index[path.name]
            priorities = {r["priority"] for r in yaml.safe_load(path.read_text())}
            allowed = level_map[entry["level"].upper()]
            assert priorities & allowed, \
                f"{path.name}: index level {entry['level']} maps to {allowed}, file has {priorities}"

    def test_index_detects_ids_exist_in_taxonomy(self):
        taxonomy = json.loads((CORPUS / "taxonomy" / "taxonomy.json").read_text())
        known = {t["id"] for t in taxonomy["techniques"]}
        for rule in load_index()["rules"]:
            unknown = set(rule["detects"]) - known
            assert not unknown, f"{rule['id']} references unknown techniques: {unknown}"

    def test_sigma_files_are_present_and_indexed(self):
        on_disk = {p.name for p in SIGMA_DIR.glob("*.yml")}
        assert on_disk, "no Sigma rules found"
        indexed = {r["file"].split("/")[-1] for r in load_index()["rules"] if r["engine"] == "sigma"}
        assert on_disk == indexed, f"sigma index/disk mismatch: {on_disk ^ indexed}"

    def test_every_sigma_rule_has_a_valid_attack_tag(self):
        """Tags must be real ATT&CK references.

        Regression: `attack.escape` (invented) and `attack.privilege_escalation`
        (underscore) are both rejected by `sigma check`; ATT&CK's own tactic
        naming is hyphenated.
        """
        tactics = {
            "reconnaissance", "resource-development", "initial-access", "execution",
            "persistence", "privilege-escalation", "defense-evasion", "credential-access",
            "discovery", "lateral-movement", "collection", "command-and-control",
            "exfiltration", "impact",
        }
        for path in sorted(SIGMA_DIR.glob("*.yml")):
            doc = yaml.safe_load(path.read_text())
            for tag in doc.get("tags", []):
                if not tag.startswith("attack."):
                    continue
                ref = tag[len("attack."):]
                ok = (ref in tactics
                      or (len(ref) > 1 and ref[0] in "tgs" and ref[1:].split(".")[0].isdigit()))
                assert ok, f"{path.name}: invalid ATT&CK tag {tag!r}"
