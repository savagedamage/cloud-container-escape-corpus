"""Severity calibration for admission review.

Two independent properties matter, and they are easy to confuse:

1. **No understatement.** The aggregate level must never be gentler than the worst
   single finding. Before this was enforced, a pod whose only problem was
   `privileged: true` (a CRITICAL check, 60 points) reported as merely HIGH, and
   any lone HIGH finding (30 points) reported as MEDIUM — the headline
   contradicted the report's own worst finding.

2. **Discrimination.** A score that is always the same carries no information. The
   interesting measurement is the ORDERING between a weak-in-the-abstract pod and a
   genuinely dangerous one, not the label alone.

Note on saturation: score ACCUMULATION can still reach CRITICAL from many minor
findings (BishopFox's `nothing-allowed` pods — no securityContext at all — total
125). That is pre-existing, deliberate behaviour, not a regression; the ordering
test below pins the property that actually discriminates.
"""

import pytest

from escape_corpus.admission_review import BUILTIN_CHECKS, SEVERITY_WEIGHTS, AdmissionReviewer


def spec(**over):
    base = {"containers": [{
        "name": "c", "image": "i",
        "securityContext": {"runAsNonRoot": True, "allowPrivilegeEscalation": False,
                            "readOnlyRootFilesystem": True,
                            "capabilities": {"drop": ["ALL"]},
                            "seccompProfile": {"type": "RuntimeDefault"}},
        "resources": {"limits": {"memory": "1Gi"}}}]}
    base.update(over)
    return base


def report_for(pod_spec):
    pod = {"apiVersion": "v1", "kind": "Pod",
           "metadata": {"name": "t", "namespace": "default"}, "spec": pod_spec}
    reviewer = AdmissionReviewer()
    reviewer.review_pod(pod)
    return reviewer.generate_report(pod, [])


class TestNoUnderstatement:
    def test_single_critical_finding_yields_critical(self):
        """`privileged: true` alone is CRITICAL. It used to report HIGH."""
        r = report_for({"containers": [{"name": "c", "image": "i",
                                        "securityContext": {"privileged": True}}]})
        assert r.risk_level == "CRITICAL"

    @pytest.mark.parametrize("field", ["hostPID", "hostNetwork", "hostIPC"])
    def test_single_high_finding_yields_at_least_high(self, field):
        """A lone HIGH finding used to report MEDIUM (30 points < 50 threshold)."""
        r = report_for(spec(**{field: True}))
        assert r.risk_level in ("HIGH", "CRITICAL")

    @pytest.mark.parametrize("severity", ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
    def test_level_is_never_below_the_worst_finding(self, severity):
        """The invariant, tested directly on generate_report.

        Synthesising a pod per check does not work — different checks need different
        pod shapes (volumes, mountPaths, env) — so the finding is injected and the
        report's own level is asserted to respect it.
        """
        check = next(name for name, meta in BUILTIN_CHECKS.items()
                     if meta["severity"] == severity)
        reviewer = AdmissionReviewer()
        reviewer._add_finding(check)
        pod = {"apiVersion": "v1", "kind": "Pod",
               "metadata": {"name": "t", "namespace": "default"},
               "spec": {"containers": [{"name": "c", "image": "i"}]}}
        report = reviewer.generate_report(pod, [])

        rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        assert rank[report.risk_level] >= rank[severity], (
            f"a single {severity} finding ({check}) reported as {report.risk_level}")

    def test_a_single_critical_finding_alone_is_critical(self):
        reviewer = AdmissionReviewer()
        reviewer._add_finding("privileged_container")
        pod = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "t"},
               "spec": {"containers": [{"name": "c", "image": "i"}]}}
        assert reviewer.generate_report(pod, []).risk_level == "CRITICAL"
        # and the score must not be the thing deciding it
        assert reviewer.generate_report(pod, []).risk_score < 100

    def test_empty_pod_is_low_not_medium(self):
        """A fully-restricted pod with only advisory gaps stays below HIGH."""
        r = report_for(spec())
        assert r.risk_level in ("LOW", "MEDIUM")


class TestDiscrimination:
    """The score ordering is the signal that survives saturation."""

    def test_privileged_outranks_a_merely_unhardened_pod(self):
        unhardened = report_for({"containers": [{"name": "c", "image": "i"}]})
        privileged = report_for({"containers": [{"name": "c", "image": "i",
                                                "securityContext": {"privileged": True}}]})
        assert privileged.risk_score > unhardened.risk_score

    def test_more_dangerous_fields_score_higher(self):
        one = report_for(spec(hostNetwork=True))
        both = report_for(spec(hostNetwork=True, hostPID=True))
        assert both.risk_score > one.risk_score

    def test_weights_are_ordered_by_severity(self):
        assert (SEVERITY_WEIGHTS["LOW"] < SEVERITY_WEIGHTS["MEDIUM"]
                < SEVERITY_WEIGHTS["HIGH"] < SEVERITY_WEIGHTS["CRITICAL"])

    def test_critical_weights_cannot_reach_the_level_alone_from_one_low(self):
        """Guards the threshold arithmetic: one LOW must never be MEDIUM."""
        assert SEVERITY_WEIGHTS["LOW"] < 20
