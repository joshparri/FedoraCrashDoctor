"""Tests for incident fingerprinting/recurrence: grouping by pattern
(failure_scope + leading mechanisms), never by per-occurrence detail."""
from __future__ import annotations

from datetime import datetime, timedelta

from incident_fingerprint import (
    build_families,
    compute_fingerprint,
    dormancy_note,
    frequency_trend,
)


def _incident(incident_id, anchor, failure_scope="whole_system", mechanism_tags=("gpu_drm",),
              confidence="moderate", **overrides):
    base = {
        "incident_id": incident_id,
        "incident_anchor_ts": anchor,
        "failure_scope": failure_scope,
        "mechanism_tags": list(mechanism_tags),
        "confidence": confidence,
    }
    base.update(overrides)
    return base


class TestComputeFingerprint:
    def test_same_scope_and_mechanisms_give_the_same_fingerprint(self):
        a = _incident("inc_1", "2026-09-01T10:00:00")
        b = _incident("inc_2", "2026-09-05T14:00:00")
        assert compute_fingerprint(a) == compute_fingerprint(b)

    def test_fingerprint_ignores_incident_id_and_timestamp(self):
        """Harmless PID/timestamp variation must not split a family."""
        a = _incident("inc_completely_different_id", "2026-01-01T00:00:00")
        b = _incident("inc_another_id_entirely", "2026-12-31T23:59:59")
        assert compute_fingerprint(a) == compute_fingerprint(b)

    def test_different_failure_scope_gives_different_fingerprint(self):
        a = _incident("inc_1", "2026-09-01T10:00:00", failure_scope="whole_system")
        b = _incident("inc_2", "2026-09-01T10:00:00", failure_scope="application")
        assert compute_fingerprint(a) != compute_fingerprint(b)

    def test_different_leading_mechanism_gives_different_fingerprint(self):
        a = _incident("inc_1", "2026-09-01T10:00:00", mechanism_tags=("gpu_drm",))
        b = _incident("inc_2", "2026-09-01T10:00:00", mechanism_tags=("memory_pressure",))
        assert compute_fingerprint(a) != compute_fingerprint(b)

    def test_low_ranked_mechanism_difference_beyond_depth_does_not_split(self):
        a = _incident("inc_1", "2026-09-01T10:00:00", mechanism_tags=("gpu_drm", "memory_pressure", "thermal"))
        b = _incident("inc_2", "2026-09-01T10:00:00", mechanism_tags=("gpu_drm", "memory_pressure", "storage_filesystem"))
        assert compute_fingerprint(a) == compute_fingerprint(b)


class TestBuildFamilies:
    def test_similar_incidents_group_into_one_family(self):
        incidents = [
            _incident("inc_1", "2026-09-01T10:00:00"),
            _incident("inc_2", "2026-09-05T10:00:00"),
            _incident("inc_3", "2026-09-09T10:00:00"),
        ]
        families = build_families(incidents)
        assert len(families) == 1
        assert families[0].count == 3
        assert set(families[0].incident_ids) == {"inc_1", "inc_2", "inc_3"}

    def test_materially_different_incidents_do_not_group(self):
        incidents = [
            _incident("inc_1", "2026-09-01T10:00:00", failure_scope="whole_system", mechanism_tags=("gpu_drm",)),
            _incident("inc_2", "2026-09-02T10:00:00", failure_scope="application", mechanism_tags=("application_fault",)),
        ]
        families = build_families(incidents)
        assert len(families) == 2

    def test_first_seen_and_last_seen_are_correct_regardless_of_input_order(self):
        incidents = [
            _incident("inc_late", "2026-09-09T10:00:00"),
            _incident("inc_early", "2026-09-01T10:00:00"),
            _incident("inc_mid", "2026-09-05T10:00:00"),
        ]
        family = build_families(incidents)[0]
        assert family.first_seen == "2026-09-01T10:00:00"
        assert family.last_seen == "2026-09-09T10:00:00"

    def test_families_sorted_most_recurring_first(self):
        incidents = (
            [_incident(f"inc_a{i}", f"2026-09-0{i+1}T10:00:00", failure_scope="whole_system",
                        mechanism_tags=("gpu_drm",)) for i in range(3)]
            + [_incident("inc_b1", "2026-09-10T10:00:00", failure_scope="application",
                          mechanism_tags=("application_fault",))]
        )
        families = build_families(incidents)
        assert families[0].count == 3
        assert families[1].count == 1

    def test_incident_ids_and_fingerprint_id_are_separate_namespaces(self):
        incidents = [_incident("inc_1", "2026-09-01T10:00:00")]
        family = build_families(incidents)[0]
        assert family.fingerprint.startswith("fam_")
        assert family.incident_ids[0].startswith("inc_")
        assert family.fingerprint != family.incident_ids[0]


class TestFrequencyTrend:
    def test_insufficient_data_below_four_occurrences(self):
        incidents = [_incident(f"inc_{i}", f"2026-09-0{i+1}T10:00:00") for i in range(3)]
        family = build_families(incidents)[0]
        assert frequency_trend(family) == "insufficient_data"

    def test_increasing_frequency_detected(self):
        # gaps shrink from ~10 days to ~1 day
        anchors = ["2026-01-01", "2026-01-11", "2026-01-21", "2026-01-22", "2026-01-23"]
        incidents = [_incident(f"inc_{i}", f"{a}T00:00:00") for i, a in enumerate(anchors)]
        family = build_families(incidents)[0]
        assert frequency_trend(family) == "increasing"

    def test_decreasing_frequency_detected(self):
        anchors = ["2026-01-01", "2026-01-02", "2026-01-03", "2026-01-13", "2026-01-23"]
        incidents = [_incident(f"inc_{i}", f"{a}T00:00:00") for i, a in enumerate(anchors)]
        family = build_families(incidents)[0]
        assert frequency_trend(family) == "decreasing"

    def test_stable_frequency_detected(self):
        anchors = ["2026-01-01", "2026-01-08", "2026-01-15", "2026-01-22"]
        incidents = [_incident(f"inc_{i}", f"{a}T00:00:00") for i, a in enumerate(anchors)]
        family = build_families(incidents)[0]
        assert frequency_trend(family) == "stable"


class TestDormancyNote:
    def test_no_note_with_insufficient_history(self):
        incidents = [_incident(f"inc_{i}", f"2026-01-0{i+1}T00:00:00") for i in range(2)]
        family = build_families(incidents)[0]
        assert dormancy_note(family, datetime(2026, 6, 1)) is None

    def test_no_note_when_gap_since_last_is_typical(self):
        anchors = ["2026-01-01", "2026-01-08", "2026-01-15"]
        incidents = [_incident(f"inc_{i}", f"{a}T00:00:00") for i, a in enumerate(anchors)]
        family = build_families(incidents)[0]
        assert dormancy_note(family, datetime(2026, 1, 20)) is None

    def test_note_when_dormant_far_longer_than_typical_gap(self):
        anchors = ["2026-01-01", "2026-01-08", "2026-01-15"]
        incidents = [_incident(f"inc_{i}", f"{a}T00:00:00") for i, a in enumerate(anchors)]
        family = build_families(incidents)[0]
        note = dormancy_note(family, datetime(2026, 3, 1))
        assert note is not None
        assert "does not confirm" in note

    def test_note_never_claims_the_issue_is_fixed(self):
        anchors = ["2026-01-01", "2026-01-08", "2026-01-15"]
        incidents = [_incident(f"inc_{i}", f"{a}T00:00:00") for i, a in enumerate(anchors)]
        family = build_families(incidents)[0]
        note = dormancy_note(family, datetime(2026, 3, 1))
        assert "fixed" not in note.lower()
        assert "resolved" in note.lower() and "does not confirm" in note.lower()
