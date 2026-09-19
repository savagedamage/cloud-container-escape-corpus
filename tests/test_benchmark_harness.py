"""Tests for the BadPods benchmark harness (scripts/benchmark_badpods.py).

The published benchmark numbers are only meaningful if the harness normalises
workload kinds correctly — a Deployment whose template is read wrongly would
score as an empty pod and silently inflate "misses".
"""

import importlib.util
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
_loader = importlib.util.spec_from_file_location("benchmark_badpods", ROOT / "scripts" / "benchmark_badpods.py")
assert _loader is not None and _loader.loader is not None
bench = importlib.util.module_from_spec(_loader)
_loader.loader.exec_module(bench)


POD = {"kind": "Pod", "metadata": {"name": "p"},
       "spec": {"containers": [{"name": "c", "image": "i", "securityContext": {"privileged": True}}]}}

DEPLOYMENT = {"kind": "Deployment", "metadata": {"name": "d"},
              "spec": {"template": {"spec": {"hostPID": True,
                                             "containers": [{"name": "c", "image": "i"}]}}}}

CRONJOB = {"kind": "CronJob", "metadata": {"name": "cj"},
           "spec": {"jobTemplate": {"spec": {"template": {"spec": {
               "hostNetwork": True, "containers": [{"name": "c", "image": "i"}]}}}}}}

DAEMONSET = {"kind": "DaemonSet", "metadata": {"name": "ds"},
             "spec": {"template": {"spec": {"hostIPC": True,
                                            "containers": [{"name": "c", "image": "i"}]}}}}


class TestNormalisation:
    def test_pod_is_passed_through(self):
        pod = bench.to_pod_spec(POD)
        assert pod["spec"]["containers"][0]["securityContext"]["privileged"] is True

    def test_deployment_template_is_unwrapped(self):
        assert bench.to_pod_spec(DEPLOYMENT)["spec"]["hostPID"] is True

    def test_cronjob_nests_one_level_deeper(self):
        assert bench.to_pod_spec(CRONJOB)["spec"]["hostNetwork"] is True

    def test_daemonset_template_is_unwrapped(self):
        assert bench.to_pod_spec(DAEMONSET)["spec"]["hostIPC"] is True

    def test_metadata_is_preserved(self):
        pod = bench.to_pod_spec(DEPLOYMENT)
        assert pod["metadata"]["name"] == "d"

    def test_unknown_wrapper_kinds_do_not_crash(self):
        pod = bench.to_pod_spec({"kind": "Widget", "spec": {}})
        assert pod["spec"] == {}


class TestEndToEndOnSyntheticCorpus:
    """Run the harness against a miniature corpus with known answers."""

    def _write(self, tmp_path, level, kind_doc, name="m.yaml"):
        # BadPods layout: manifests/<level>/<kind>/<file>.yaml
        d = tmp_path / "manifests" / level / "pod"
        d.mkdir(parents=True, exist_ok=True)
        (d / name).write_text(yaml.safe_dump(kind_doc))
        return d

    def test_flags_dangerous_and_passes_restricted(self, tmp_path, monkeypatch, capsys):
        self._write(tmp_path, "everything-allowed", POD)
        self._write(tmp_path, "nothing-allowed", {
            "kind": "Pod", "metadata": {"name": "good"},
            "spec": {
                "securityContext": {"runAsNonRoot": True, "runAsUser": 1000,
                                    "seccompProfile": {"type": "RuntimeDefault"}},
                "automountServiceAccountToken": False, "serviceAccountName": "app",
                "containers": [{"name": "c", "image": "i@sha256:" + "b" * 64,
                                "securityContext": {"allowPrivilegeEscalation": False,
                                                    "readOnlyRootFilesystem": True,
                                                    "capabilities": {"drop": ["ALL"]}},
                                "resources": {"limits": {"cpu": "1", "memory": "1Gi"}}}]}})

        monkeypatch.setattr("sys.argv",
                            ["benchmark_badpods.py", str(tmp_path),
                             "--json", str(tmp_path / "out.json")])
        assert bench.main() == 0
        out = json.loads((tmp_path / "out.json").read_text())
        by_level = out["by_level"]
        assert by_level["everything-allowed"]["flagged"] == 1
        # the restricted pod must not be flagged CRITICAL/HIGH
        assert by_level["nothing-allowed"]["flagged"] == 0

    def test_empty_corpus_exits_nonzero(self, tmp_path, monkeypatch, capsys):
        (tmp_path / "manifests").mkdir()
        monkeypatch.setattr("sys.argv", ["benchmark_badpods.py", str(tmp_path)])
        assert bench.main() == 2

    def test_load_yaml_skips_non_workload_documents(self, tmp_path):
        """A Service or ConfigMap in the tree must not be scored as a pod."""
        f = tmp_path / "mixed.yaml"
        f.write_text(yaml.safe_dump_all([
            {"kind": "Service", "metadata": {"name": "svc"}, "spec": {}},
            {"kind": "ConfigMap", "metadata": {"name": "cm"}},
            POD,
        ]))
        docs = bench.load_yaml(f)
        assert len(docs) == 1 and docs[0]["kind"] == "Pod"
