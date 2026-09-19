"""Tests for escape_corpus.cli — dispatch, browsing subcommands, and validation.

`validate` is the repo's consistency gate, so its failure path is tested too:
a gate that cannot fail is not a gate.
"""

import json
import sys

import pytest

from escape_corpus import cli


class TestCorpusRoot:
    def test_resolves_to_the_repo_root(self):
        root = cli._find_corpus_root()
        assert (root / "corpus" / "taxonomy" / "taxonomy.json").exists()
        assert (root / "schemas" / "taxonomy.schema.json").exists()

    def test_missing_data_raises_with_guidance(self, monkeypatch, tmp_path):
        monkeypatch.setattr(cli, "Path", cli.Path)   # keep Path API explicit
        import pathlib
        real_exists = pathlib.Path.exists

        def fake_exists(self):
            if self.name == "taxonomy.json":
                return False
            return real_exists(self)

        monkeypatch.setattr(pathlib.Path, "exists", fake_exists)
        monkeypatch.setattr(cli.sys, "prefix", str(tmp_path / "nope"))
        with pytest.raises(FileNotFoundError, match="pip install"):
            cli._find_corpus_root()


class TestTechniques:
    def test_list_shows_every_technique(self, capsys):
        cli.main(["techniques"])
        out = capsys.readouterr().out
        for tid in ("CE-001", "CE-005", "CE-010"):
            assert tid in out

    def test_detail_by_id(self, capsys):
        cli.main(["techniques", "--id", "ce-003"])       # case-insensitive
        out = capsys.readouterr().out
        assert "CE-003" in out and "rbac" in out.lower()

    def test_json_output_is_machine_readable(self, capsys):
        cli.main(["techniques", "--id", "CE-001", "--json"])
        doc = json.loads(capsys.readouterr().out)
        assert doc["id"] == "CE-001"
        assert doc["mitre_attack"], "MITRE mapping must be present"

    def test_unknown_id_exits_nonzero(self, capsys):
        with pytest.raises(SystemExit) as exc:
            cli.main(["techniques", "--id", "CE-999"])
        assert exc.value.code == 1
        assert "Unknown technique" in capsys.readouterr().err


class TestRules:
    def test_lists_all_rules(self, capsys):
        cli.main(["rules"])
        out = capsys.readouterr().out
        assert "SIGMA-001" in out and "FALCO-008" in out

    def test_filters_by_technique(self, capsys):
        cli.main(["rules", "--technique", "CE-007"])
        out = capsys.readouterr().out
        assert "SIGMA-003" in out and "FALCO-008" in out
        assert "SIGMA-005" not in out          # runc rule covers CE-005 only

    def test_json_shape(self, capsys):
        cli.main(["rules", "--technique", "CE-001", "--json"])
        rules = json.loads(capsys.readouterr().out)
        assert rules and all({"id", "engine", "title"} <= set(r) for r in rules)


class TestSideChannels:
    def test_lists_surfaces(self, capsys):
        cli.main(["side-channels"])
        assert "SC-001" in capsys.readouterr().out

    def test_detail_json(self, capsys):
        cli.main(["side-channels", "--id", "SC-005", "--json"])
        doc = json.loads(capsys.readouterr().out)
        assert doc["id"] == "SC-005" and doc["risk"]

    def test_unknown_surface_exits(self, capsys):
        with pytest.raises(SystemExit) as exc:
            cli.main(["side-channels", "--id", "SC-999"])
        assert exc.value.code == 1


class TestSchemas:
    def test_lists_every_schema(self, capsys):
        cli.main(["schemas"])
        out = capsys.readouterr().out
        for name in ("taxonomy.schema.json", "image-diff.schema.json",
                     "baseline-snapshot.schema.json", "admission-report.schema.json",
                     "side-channels.schema.json"):
            assert name in out


class TestValidateGate:
    def test_real_corpus_passes(self, capsys):
        try:
            cli.main(["validate"])
        except SystemExit as e:                # pragma: no cover - failure path
            pytest.fail(f"validate failed on the shipped corpus: {e}")
        assert "OK" in capsys.readouterr().out

    def test_broken_taxonomy_fails_the_gate(self, monkeypatch, tmp_path, capsys):
        bad = tmp_path / "taxonomy.json"
        bad.write_text(json.dumps({
            "schema_version": "1.0", "name": "broken",
            "techniques": [
                {"id": "CE-001", "name": "a", "category": "c", "mitre_attack": ["T1611"],
                 "risk": {"prevalence": "low", "impact": "low", "detectability": "low", "overall": "low"},
                 "prerequisites": ["x"], "guide": "techniques/missing.md",
                 "detection_rule_ids": ["SIGMA-999"]},
                {"id": "CE-001", "name": "dup", "category": "c", "mitre_attack": ["T1611"],
                 "risk": {"prevalence": "low", "impact": "low", "detectability": "low", "overall": "low"},
                 "prerequisites": ["x"], "guide": "techniques/missing.md",
                 "detection_rule_ids": []},
            ],
            "detection_rules": {},
        }))
        monkeypatch.setattr(cli, "TAXONOMY_PATH", bad)
        with pytest.raises(SystemExit) as exc:
            cli.main(["validate"])
        assert exc.value.code == 1
        err = capsys.readouterr().out
        assert "duplicate technique ids" in err
        assert "guide file missing" in err
        assert "unknown rule" in err


class TestDelegation:
    """The unified CLI must forward to the tool mains with correct argv."""

    def test_image_diff_argv_forwarding(self, monkeypatch):
        seen = {}
        import escape_corpus.image_diff as image_diff

        def fake_main():
            seen["argv"] = list(sys.argv)

        monkeypatch.setattr(image_diff, "main", fake_main)
        cli.main(["image-diff", "old:1", "new:2", "-o", "out.json", "-v"])
        assert seen["argv"] == ["image-diff", "old:1", "new:2", "-o", "out.json", "-v"]

    def test_baseline_argv_forwarding(self, monkeypatch):
        seen = {}
        import escape_corpus.runtime_baseline as rb

        def fake_main():
            seen["argv"] = list(sys.argv)

        monkeypatch.setattr(rb, "main", fake_main)
        cli.main(["baseline", "verify", "--container", "c1", "--runtime", "docker",
                  "--baseline", "b.json", "--output", "o.json"])
        argv = seen["argv"]
        assert argv[0] == "runtime-baseline" and argv[1] == "verify"
        assert "--container" in argv and "c1" in argv and "--runtime" in argv
        assert "--baseline" in argv and "--output" in argv

    def test_admit_argv_forwarding(self, monkeypatch):
        seen = {}
        import escape_corpus.admission_review as ar

        def fake_main():
            seen["argv"] = list(sys.argv)

        monkeypatch.setattr(ar, "main", fake_main)
        cli.main(["admit", "--pod", "p.yaml", "--policies", "pol.yaml", "--json"])
        assert seen["argv"][:3] == ["admission-review", "--pod", "p.yaml"]
        assert "--policies" in seen["argv"] and "--json" in seen["argv"]

    def test_version_flag(self, capsys):
        with pytest.raises(SystemExit) as exc:
            cli.main(["--version"])
        assert exc.value.code == 0
        assert "escape-corpus" in capsys.readouterr().out
