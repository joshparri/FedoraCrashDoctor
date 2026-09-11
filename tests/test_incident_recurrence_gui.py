"""Tests for MainWindow._attach_incident_recurrence: the unprivileged,
GUI-side step that upgrades collect()'s family-less hypothesis
explanations with real cross-scan recurrence context, using previously
saved scan-*.json reports. Deliberately never touches the real
~/Documents folder -- report_dir is redirected to a tmp_path first.
"""
import json
import os
import sys

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("QT_QPA_PLATFORM") != "offscreen",
    reason="Requires QT_QPA_PLATFORM=offscreen",
)


def _make_window(tmp_path):
    from PySide6.QtWidgets import QApplication
    from fedora_crash_doctor import MainWindow

    app = QApplication.instance() or QApplication(sys.argv)
    window = MainWindow()
    window.report_dir = tmp_path  # never touch the real ~/Documents folder
    return window


def _incident(incident_id, anchor, failure_scope="whole_system", mechanism_tags=("gpu_drm",)):
    return {
        "incident_id": incident_id,
        "incident_anchor_ts": anchor,
        "failure_scope": failure_scope,
        "mechanism_tags": list(mechanism_tags),
        "confidence": "moderate",
        "hypotheses": [
            {"title": "Display-stack or KWin Wayland freeze", "category": "Graphics", "score": 0.5,
             "confidence": "moderate", "supports": [], "against": [], "next_test": "x"},
        ],
        "evidence_completeness": {
            "journal": "complete", "coredump": "unavailable",
            "canary_telemetry": "not_collected", "desktop_heartbeat": "not_collected",
            "user_observations": "not_collected",
        },
    }


def _write_scan(report_dir, name, incidents, generated="2026-09-01T00:00:00"):
    (report_dir / name).write_text(json.dumps({"metadata": {"generated": generated}, "incidents": incidents}))


class TestAttachIncidentRecurrence:
    def test_no_incidents_is_a_no_op(self, tmp_path):
        window = _make_window(tmp_path)
        report = {"incidents": []}
        window._attach_incident_recurrence(report)
        assert "incident_families" not in report

    def test_first_occurrence_gets_no_recurrence_upgrade(self, tmp_path):
        """With no prior history, the single-scan family only has count=1,
        so it's filtered out of incident_families (>1 only) and the
        collect()-attached family-less explanation is left as-is."""
        window = _make_window(tmp_path)
        incident = _incident("inc_1", "2026-09-05T10:00:00")
        incident["hypothesis_explanations"] = [{"mechanism": "x", "recurrence_context": None}]
        report = {"metadata": {"generated": "2026-09-05T10:05:00"}, "incidents": [incident]}
        window._attach_incident_recurrence(report)
        assert report.get("incident_families", []) == []

    def test_recurring_incident_gets_recurrence_context_attached(self, tmp_path):
        _write_scan(tmp_path, "scan-1.json", [_incident("inc_old", "2026-09-01T10:00:00")],
                    generated="2026-09-01T10:05:00")
        window = _make_window(tmp_path)
        incident = _incident("inc_new", "2026-09-05T10:00:00")
        report = {"metadata": {"generated": "2026-09-05T10:05:00"}, "incidents": [incident]}
        window._attach_incident_recurrence(report)

        assert len(report["incident_families"]) == 1
        assert report["incident_families"][0]["count"] == 2
        explanations = incident["hypothesis_explanations"]
        assert explanations[0]["recurrence_context"] is not None
        assert "2 time(s)" in explanations[0]["recurrence_context"]

    def test_current_scan_is_not_double_counted_if_already_saved(self, tmp_path):
        incident = _incident("inc_1", "2026-09-05T10:00:00")
        generated = "2026-09-05T10:05:00"
        _write_scan(tmp_path, "scan-self.json", [incident], generated=generated)

        window = _make_window(tmp_path)
        report = {"metadata": {"generated": generated}, "incidents": [incident]}
        window._attach_incident_recurrence(report)
        # Only counted once (from `incidents`), not twice (also from the
        # already-saved file with the same metadata.generated).
        assert report.get("incident_families", []) == []

    def test_a_broken_history_file_does_not_crash_the_scan(self, tmp_path):
        (tmp_path / "scan-broken.json").write_text("{not valid json")
        window = _make_window(tmp_path)
        incident = _incident("inc_1", "2026-09-05T10:00:00")
        report = {"metadata": {"generated": "2026-09-05T10:05:00"}, "incidents": [incident]}
        window._attach_incident_recurrence(report)  # must not raise
