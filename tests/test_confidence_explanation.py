"""Tests for explainable confidence: structuring, not replacing,
collector.py's existing ranked hypotheses."""
from __future__ import annotations

from incident_fingerprint import IncidentFamily
from confidence_explanation import explain_hypothesis, explain_incident, format_explanation_text


def _hypothesis(title, category, confidence="moderate", supports=None, against=None, next_test="do X"):
    return {
        "title": title, "category": category, "score": 0.5, "confidence": confidence,
        "supports": supports or [], "against": against or [], "next_test": next_test,
    }


def _incident(**overrides):
    base = {
        "hypotheses": [
            _hypothesis("Display-stack or KWin Wayland freeze", "Graphics",
                        supports=["i915 error logged near the boundary"]),
            _hypothesis("Memory/swap exhaustion", "Memory", against=["MemAvailable stayed high"]),
        ],
        "mechanism_tags": ["gpu_drm", "memory_pressure"],
        "evidence_completeness": {
            "journal": "complete", "coredump": "unavailable",
            "canary_telemetry": "not_collected", "desktop_heartbeat": "not_collected",
            "user_observations": "not_collected",
        },
    }
    base.update(overrides)
    return base


class TestExplainHypothesis:
    def test_explains_the_top_hypothesis(self):
        incident = _incident()
        explanation = explain_hypothesis(incident, incident["hypotheses"][0], 0)
        assert explanation["mechanism"] == "Display-stack or KWin Wayland freeze"
        assert explanation["confidence"] == "moderate"
        assert explanation["supporting_evidence"] == ["i915 error logged near the boundary"]

    def test_competing_hypotheses_exclude_the_one_being_explained(self):
        incident = _incident()
        explanation = explain_hypothesis(incident, incident["hypotheses"][0], 0)
        assert explanation["competing_hypotheses"] == ["Memory/swap exhaustion"]

        explanation2 = explain_hypothesis(incident, incident["hypotheses"][1], 1)
        assert explanation2["competing_hypotheses"] == ["Display-stack or KWin Wayland freeze"]

    def test_missing_evidence_reflects_evidence_completeness_gaps(self):
        incident = _incident()
        explanation = explain_hypothesis(incident, incident["hypotheses"][0], 0)
        missing_text = " ".join(explanation["missing_evidence"])
        assert "coredump" in missing_text.lower()
        assert "observations" in missing_text.lower()
        assert "canary" in missing_text.lower() or "heartbeat" in missing_text.lower()

    def test_complete_evidence_produces_no_missing_evidence_entries(self):
        incident = _incident(evidence_completeness={
            "journal": "complete", "coredump": "complete",
            "canary_telemetry": "complete", "desktop_heartbeat": "complete", "user_observations": "complete",
        })
        explanation = explain_hypothesis(incident, incident["hypotheses"][0], 0)
        assert explanation["missing_evidence"] == []

    def test_mechanism_specific_strengthen_weaken_for_known_tag(self):
        incident = _incident()
        explanation = explain_hypothesis(incident, incident["hypotheses"][0], 0)
        assert "GPU" in explanation["what_would_strengthen"] or "graphics" in explanation["what_would_strengthen"].lower()
        assert explanation["what_would_weaken"]

    def test_unknown_mechanism_tag_gets_a_generic_fallback_not_a_crash(self):
        incident = _incident(mechanism_tags=["some_new_tag_not_in_the_table"])
        explanation = explain_hypothesis(incident, incident["hypotheses"][0], 0)
        assert explanation["what_would_strengthen"]
        assert explanation["what_would_weaken"]

    def test_recurrence_context_included_when_family_given(self):
        family = IncidentFamily(
            fingerprint="fam_abc", failure_scope="whole_system", dominant_mechanisms=["gpu_drm"],
            incident_ids=["inc_1", "inc_2"], anchors=["2026-09-01T10:00:00", "2026-09-05T10:00:00"],
            confidence_trend=["moderate", "moderate"], count=2,
        )
        incident = _incident()
        explanation = explain_hypothesis(incident, incident["hypotheses"][0], 0, family=family)
        assert explanation["recurrence_context"] is not None
        assert "2 time(s)" in explanation["recurrence_context"]

    def test_no_family_means_no_recurrence_context(self):
        incident = _incident()
        explanation = explain_hypothesis(incident, incident["hypotheses"][0], 0)
        assert explanation["recurrence_context"] is None

    def test_best_next_test_comes_from_the_existing_hypothesis(self):
        incident = _incident()
        explanation = explain_hypothesis(incident, incident["hypotheses"][0], 0)
        assert explanation["best_next_test"] == "do X"


class TestExplainIncident:
    def test_explains_every_hypothesis_in_rank_order(self):
        incident = _incident()
        explanations = explain_incident(incident)
        assert len(explanations) == 2
        assert explanations[0]["mechanism"] == "Display-stack or KWin Wayland freeze"
        assert explanations[1]["mechanism"] == "Memory/swap exhaustion"

    def test_no_hypotheses_gives_empty_list_not_an_error(self):
        assert explain_incident(_incident(hypotheses=[])) == []


class TestFormatExplanationText:
    def test_produces_the_expected_section_headings(self):
        incident = _incident()
        explanation = explain_hypothesis(incident, incident["hypotheses"][0], 0)
        text = format_explanation_text(explanation)
        assert "Likely mechanism:" in text
        assert "Confidence:" in text
        assert "Supports:" in text
        assert "Next useful evidence:" in text

    def test_never_hides_a_bare_score_as_the_only_output(self):
        """The whole point of this module: there must be no path that
        renders only a number with nothing else."""
        incident = _incident()
        explanation = explain_hypothesis(incident, incident["hypotheses"][0], 0)
        text = format_explanation_text(explanation)
        assert len(text.splitlines()) > 3
