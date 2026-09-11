"""Tests for cross-scan incident history: reading previously saved scan
reports to enable real fingerprinting/recurrence across scans, not just
within one scan's own incidents."""
from __future__ import annotations

import json

from incident_history import family_for_incident, families_from_history, load_incident_history


def _write_scan(tmp_path, name, incidents, generated="2026-09-01T00:00:00"):
    path = tmp_path / name
    path.write_text(json.dumps({"metadata": {"generated": generated}, "incidents": incidents}))
    return path


def _incident(incident_id, anchor, failure_scope="whole_system", mechanism_tags=("gpu_drm",)):
    return {
        "incident_id": incident_id,
        "incident_anchor_ts": anchor,
        "failure_scope": failure_scope,
        "mechanism_tags": list(mechanism_tags),
        "confidence": "moderate",
    }


class TestLoadIncidentHistory:
    def test_empty_directory_returns_empty_list(self, tmp_path):
        assert load_incident_history(tmp_path) == []

    def test_missing_directory_returns_empty_list(self, tmp_path):
        assert load_incident_history(tmp_path / "does-not-exist") == []

    def test_reads_incidents_from_all_scan_files(self, tmp_path):
        _write_scan(tmp_path, "scan-1.json", [_incident("inc_1", "2026-09-01T10:00:00")])
        _write_scan(tmp_path, "scan-2.json", [_incident("inc_2", "2026-09-02T10:00:00")])
        history = load_incident_history(tmp_path)
        assert {i["incident_id"] for i in history} == {"inc_1", "inc_2"}

    def test_ignores_non_scan_files(self, tmp_path):
        (tmp_path / "not-a-scan.json").write_text(json.dumps({"incidents": [_incident("inc_x", "t")]}))
        assert load_incident_history(tmp_path) == []

    def test_malformed_file_is_skipped_not_fatal(self, tmp_path):
        (tmp_path / "scan-bad.json").write_text("{not valid json")
        _write_scan(tmp_path, "scan-good.json", [_incident("inc_1", "2026-09-01T10:00:00")])
        history = load_incident_history(tmp_path)
        assert len(history) == 1

    def test_non_dict_json_is_skipped_not_fatal(self, tmp_path):
        (tmp_path / "scan-list.json").write_text(json.dumps([1, 2, 3]))
        assert load_incident_history(tmp_path) == []

    def test_oversized_file_is_skipped(self, tmp_path, monkeypatch):
        import incident_history
        monkeypatch.setattr(incident_history, "MAX_FILE_SIZE_BYTES", 10)
        _write_scan(tmp_path, "scan-huge.json", [_incident("inc_1", "2026-09-01T10:00:00")])
        assert load_incident_history(tmp_path) == []

    def test_excludes_matching_generated_timestamp(self, tmp_path):
        _write_scan(tmp_path, "scan-1.json", [_incident("inc_1", "2026-09-01T10:00:00")], generated="2026-09-01T10:05:00")
        history = load_incident_history(tmp_path, exclude_generated="2026-09-01T10:05:00")
        assert history == []


class TestFamiliesFromHistory:
    def test_combines_history_and_current_incidents(self, tmp_path):
        _write_scan(tmp_path, "scan-1.json", [_incident("inc_old", "2026-09-01T10:00:00")])
        current = [_incident("inc_new", "2026-09-05T10:00:00")]
        families = families_from_history(tmp_path, current)
        assert len(families) == 1
        assert families[0].count == 2

    def test_no_history_still_works_with_current_only(self, tmp_path):
        current = [_incident("inc_new", "2026-09-05T10:00:00")]
        families = families_from_history(tmp_path, current)
        assert len(families) == 1
        assert families[0].count == 1


class TestFamilyForIncident:
    def test_finds_the_matching_family(self, tmp_path):
        current = [_incident("inc_1", "2026-09-01T10:00:00", failure_scope="whole_system", mechanism_tags=("gpu_drm",))]
        families = families_from_history(tmp_path, current)
        incident = current[0]
        found = family_for_incident(families, incident)
        assert found is not None
        assert found.fingerprint == families[0].fingerprint

    def test_returns_none_when_no_family_built_for_it(self, tmp_path):
        families = families_from_history(tmp_path, [_incident("inc_1", "t", failure_scope="whole_system")])
        unrelated = _incident("inc_2", "t2", failure_scope="application", mechanism_tags=("application_fault",))
        assert family_for_incident(families, unrelated) is None
