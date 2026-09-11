"""Tests for the structured Incident model: failure-scope classification
(kept separate from mechanism/hypothesis ranking), stable incident
identity, evidence-completeness accounting, and wiring into
collector.build_incidents().
"""
from __future__ import annotations

import incident_model
from incident_model import (
    EVIDENCE_STATES,
    FAILURE_SCOPES,
    attach_incident_identity,
    classify_failure_scope,
    compute_incident_id,
    evidence_completeness,
    mechanism_tags,
)


def _incident(**overrides):
    base = {
        "boot_id": "boot1",
        "incident_start": "2026-09-10T09:45:00",
        "incident_anchor_ts": "2026-09-10T10:00:00",
        "failure_boundary": "unclean shutdown",
        "incident_evidence": [],
        "coredumps": [],
        "hypotheses": [],
    }
    base.update(overrides)
    return base


def _evidence(finding_id):
    return {"finding": {"id": finding_id}, "line": "x", "timestamp": "2026-09-10T10:00:00"}


def _hypothesis(category, **overrides):
    h = {"title": "x", "category": category, "score": 0.5, "confidence": "moderate",
         "supports": [], "against": [], "next_test": "x"}
    h.update(overrides)
    return h


class TestClassifyFailureScope:
    def test_kernel_panic_boundary_is_whole_system(self):
        scope, reasons = classify_failure_scope(_incident(failure_boundary="kernel panic"))
        assert scope == "whole_system"
        assert reasons

    def test_watchdog_boundary_is_whole_system(self):
        scope, _ = classify_failure_scope(_incident(failure_boundary="watchdog lockup"))
        assert scope == "whole_system"

    def test_unclean_shutdown_is_whole_system_even_with_graphics_symptom(self):
        """This is the core correction: an unclean shutdown with GPU-adjacent
        evidence is scope=whole_system (confirmed) with a leading gpu_drm
        mechanism (ranked, not certain) -- not its own 'GPU incident' scope
        that implies only the GPU/desktop was affected."""
        incident = _incident(
            failure_boundary="unclean shutdown",
            incident_evidence=[_evidence("intel_display")],
            hypotheses=[_hypothesis("Graphics")],
        )
        scope, _ = classify_failure_scope(incident)
        assert scope == "whole_system"
        assert mechanism_tags(incident) == ["gpu_drm"]

    def test_clean_shutdown_boundary(self):
        scope, _ = classify_failure_scope(_incident(failure_boundary="clean shutdown"))
        assert scope == "clean_shutdown"

    def test_compositor_crash_boundary(self):
        scope, _ = classify_failure_scope(_incident(failure_boundary="compositor crash"))
        assert scope == "compositor_session"

    def test_oom_event_boundary_alone_is_unknown_scope(self):
        """An OOM kill that didn't crash the whole boot tells us memory
        pressure occurred (a mechanism), but not by itself how much of the
        system was user-visibly affected -- that's an honest 'unknown'
        scope, not a specific one."""
        scope, _ = classify_failure_scope(_incident(failure_boundary="OOM event"))
        assert scope == "unknown"

    def test_plasmashell_coredump_takes_priority(self):
        incident = _incident(failure_boundary="active session",
                              coredumps=[{"executable": "/usr/bin/plasmashell"}])
        scope, reasons = classify_failure_scope(incident)
        assert scope == "plasmashell_panel"
        assert reasons

    def test_generic_app_coredump_with_no_other_symptoms(self):
        incident = _incident(failure_boundary="active session",
                              coredumps=[{"executable": "/usr/bin/some-app"}])
        scope, _ = classify_failure_scope(incident)
        assert scope == "application"

    def test_coredump_with_other_symptoms_is_not_treated_as_app_only(self):
        incident = _incident(
            failure_boundary="active session",
            coredumps=[{"executable": "/usr/bin/some-app"}],
            incident_evidence=[_evidence("intel_display")],
        )
        scope, _ = classify_failure_scope(incident)
        assert scope != "application"

    def test_wayland_symptom_without_compositor_boundary(self):
        incident = _incident(failure_boundary="active session", incident_evidence=[_evidence("wayland")])
        scope, _ = classify_failure_scope(incident)
        assert scope == "compositor_session"

    def test_unrecognised_pattern_is_unknown_not_a_guess(self):
        scope, reasons = classify_failure_scope(_incident(failure_boundary="active session"))
        assert scope == "unknown"
        assert reasons

    def test_every_reachable_scope_is_covered(self):
        produced = {
            classify_failure_scope(_incident(failure_boundary="kernel panic"))[0],
            classify_failure_scope(_incident(failure_boundary="clean shutdown"))[0],
            classify_failure_scope(_incident(failure_boundary="compositor crash"))[0],
            classify_failure_scope(_incident(failure_boundary="OOM event"))[0],
            classify_failure_scope(_incident(failure_boundary="active session",
                                              coredumps=[{"executable": "/usr/bin/plasmashell"}]))[0],
            classify_failure_scope(_incident(failure_boundary="active session",
                                              coredumps=[{"executable": "/usr/bin/some-app"}]))[0],
            classify_failure_scope(_incident(failure_boundary="active session"))[0],
        }
        untested = set(FAILURE_SCOPES) - produced - {"desktop_environment"}
        assert not untested, (
            f"FAILURE_SCOPES has values with no covering scenario: {untested}. "
            "desktop_environment is deliberately unreachable today -- distinguishing it from "
            "compositor_session needs desktop-heartbeat telemetry not joined in yet."
        )


class TestMechanismTags:
    def test_mechanism_tags_follow_existing_hypothesis_rank_order(self):
        incident = _incident(hypotheses=[_hypothesis("Memory"), _hypothesis("Graphics")])
        assert mechanism_tags(incident) == ["memory_pressure", "gpu_drm"]

    def test_unrecognised_category_maps_to_unknown_not_a_guess(self):
        incident = _incident(hypotheses=[_hypothesis("Some New Category")])
        assert mechanism_tags(incident) == ["unknown"]

    def test_no_hypotheses_gives_no_tags(self):
        assert mechanism_tags(_incident(hypotheses=[])) == []

    def test_every_category_collector_actually_uses_is_mapped(self):
        # collector.py's build_incidents() only ever assigns these category
        # strings to a hypothesis; if a new one is added there without being
        # taught here, it would silently fall back to 'unknown' tags for
        # fingerprinting. This guards that collector.py and this mapping
        # don't drift apart silently.
        known_categories = {"Memory", "Thermals", "Graphics", "Storage", "PCIe / Network", "Firmware", "Software"}
        assert known_categories <= set(incident_model._CATEGORY_TO_MECHANISM)


class TestEvidenceCompleteness:
    def test_states_are_from_the_closed_set(self):
        result = evidence_completeness(_incident(), checks={})
        assert set(result.values()) <= set(EVIDENCE_STATES)

    def test_not_collected_when_checks_missing_entirely(self):
        result = evidence_completeness(_incident(), checks=None)
        assert result["journal"] == "not_collected"
        assert result["coredump"] == "not_collected"

    def test_unavailable_when_checked_but_nothing_found(self):
        result = evidence_completeness(_incident(), checks={"coredumps_json": {}})
        assert result["journal"] == "unavailable"
        assert result["coredump"] == "unavailable"

    def test_complete_when_evidence_present(self):
        incident = _incident(incident_evidence=[_evidence("oom")], coredumps=[{"executable": "/bin/x"}])
        result = evidence_completeness(incident, checks={"coredumps_json": {}})
        assert result["journal"] == "complete"
        assert result["coredump"] == "complete"

    def test_future_evidence_sources_are_explicitly_not_collected_not_healthy(self):
        """These must never silently read as 'checked and healthy' just
        because build_incidents() has no way to populate them yet."""
        result = evidence_completeness(_incident(), checks={"coredumps_json": {}})
        assert result["canary_telemetry"] == "not_collected"
        assert result["desktop_heartbeat"] == "not_collected"
        assert result["user_observations"] == "not_collected"


class TestIncidentIdentity:
    def test_compute_incident_id_is_stable(self):
        a = compute_incident_id("boot1", "2026-09-10T10:00:00")
        b = compute_incident_id("boot1", "2026-09-10T10:00:00")
        assert a == b

    def test_compute_incident_id_differs_for_different_boot(self):
        a = compute_incident_id("boot1", "2026-09-10T10:00:00")
        b = compute_incident_id("boot2", "2026-09-10T10:00:00")
        assert a != b

    def test_two_separate_incidents_in_one_boot_get_different_ids(self):
        a = compute_incident_id("boot1", "2026-09-10T10:00:00")
        b = compute_incident_id("boot1", "2026-09-10T14:30:00")
        assert a != b

    def test_id_unaffected_by_widening_the_evidence_window(self):
        """Simulates a later pass discovering an earlier canary sample and
        widening incident_start -- the anchor (and therefore the id) must
        not move just because the padded window did."""
        incident = _incident(incident_start="2026-09-10T09:45:00")
        before = attach_incident_identity(dict(incident), checks={})["incident_id"]
        widened = dict(incident, incident_start="2026-09-10T09:00:00")  # window widened, anchor unchanged
        after = attach_incident_identity(widened, checks={})["incident_id"]
        assert before == after

    def test_id_unaffected_by_adding_canary_evidence(self):
        incident = _incident()
        before = attach_incident_identity(dict(incident), checks={})["incident_id"]
        with_canary = dict(incident, canary_samples=[{"ts": "2026-09-10T09:59:00", "mem_available_mb": 200}])
        after = attach_incident_identity(with_canary, checks={})["incident_id"]
        assert before == after

    def test_id_unaffected_by_adding_heartbeat_evidence(self):
        incident = _incident()
        before = attach_incident_identity(dict(incident), checks={})["incident_id"]
        with_heartbeat = dict(incident, desktop_heartbeat_samples=[{"ts": "2026-09-10T09:59:30", "alive": False}])
        after = attach_incident_identity(with_heartbeat, checks={})["incident_id"]
        assert before == after

    def test_id_unaffected_by_adding_user_observations(self):
        incident = _incident()
        before = attach_incident_identity(dict(incident), checks={})["incident_id"]
        with_observation = dict(incident, user_observations=[{"question": "mouse_moved", "answer": "yes"}])
        after = attach_incident_identity(with_observation, checks={})["incident_id"]
        assert before == after

    def test_id_unaffected_by_reclassification(self):
        """The failure_boundary label itself (unclean shutdown vs kernel
        panic) is a classification of the same anchor event and must not be
        identity material -- better evidence may later re-label the same
        anchor event without it becoming "a new incident"."""
        incident = _incident(failure_boundary="unclean shutdown")
        before = attach_incident_identity(dict(incident), checks={})["incident_id"]
        reclassified = dict(incident, failure_boundary="kernel panic")
        after = attach_incident_identity(reclassified, checks={})["incident_id"]
        assert before == after

    def test_attach_incident_identity_adds_expected_keys_without_removing_existing(self):
        incident = _incident(strongest_hypothesis="Unknown")
        result = attach_incident_identity(incident, checks={})
        assert result is incident  # mutated and returned, not replaced
        assert incident["strongest_hypothesis"] == "Unknown"  # existing key untouched
        assert incident["incident_id"].startswith("inc_")
        assert incident["failure_scope"] in FAILURE_SCOPES
        assert isinstance(incident["failure_scope_reasoning"], list) and incident["failure_scope_reasoning"]
        assert incident["mechanism_tags"] == []
        assert incident["evidence_sources"] == []
        assert set(incident["evidence_completeness"].values()) <= set(EVIDENCE_STATES)


class TestIncidentModelIntegration:
    """Prove attach_incident_identity is really wired into
    collector.build_incidents(), using the same fixture style as
    tests/test_analysis.py, not just unit-tested in isolation."""

    def test_real_graphics_incident_has_whole_system_scope_and_gpu_mechanism(self):
        from collector import analyse, build_incidents

        def check(title, output):
            return {"title": title, "output": output, "category": "Software", "status": "ok",
                    "returncode": 0, "duration_seconds": 0, "command": "test"}

        checks = {
            "previous_errors": check("prev", "2026-07-29T12:26:00+1000 host kernel: i915 0000:00:02.0: [drm] *ERROR* Atomic update failure on pipe A"),
            "boot_history": check("boot", "reboot   system boot  7.1.5-200.fc44.x Wed Jul 29 12:26 - crash  (03:25)"),
            "journal_boots": check("boots", "-1 e2110b7c6f7e4e72afca6dfe736dbfb8 Wed 2026-07-29 12:26:00 AEST Wed 2026-07-29 12:26:00 AEST"),
        }
        findings, _ = analyse(checks)
        incidents, _, _ = build_incidents(findings, checks)
        assert len(incidents) == 1
        assert incidents[0]["failure_scope"] == "whole_system"
        assert incidents[0]["mechanism_tags"][0] == "gpu_drm"
        assert incidents[0]["incident_id"].startswith("inc_")
        assert incidents[0]["evidence_completeness"]["canary_telemetry"] == "not_collected"

    def test_real_bare_unclean_shutdown_has_whole_system_scope_and_no_mechanism_confidence(self):
        from collector import analyse, build_incidents

        def check(title, output):
            return {"title": title, "output": output, "category": "Software", "status": "ok",
                    "returncode": 0, "duration_seconds": 0, "command": "test"}

        checks = {
            "boot_history": check("boot", "reboot   system boot  7.1.5-200.fc44.x Wed Jul 29 12:26 - crash  (03:25)"),
            "journal_boots": check("boots", "-1 e2110b7c6f7e4e72afca6dfe736dbfb8 Wed 2026-07-29 12:26:00 AEST Wed 2026-07-29 13:26:00 AEST\n0 e2110b7c6f7e4e72afca6dfe736dbfb8 Wed 2026-07-29 13:26:00 AEST Wed 2026-07-29 13:26:00 AEST"),
        }
        findings, _ = analyse(checks)
        incidents, _, _ = build_incidents(findings, checks)
        assert len(incidents) == 1
        assert incidents[0]["failure_scope"] == "whole_system"
        # No specific evidence beyond the boundary itself -> the existing
        # catch-all "Unknown Kernel, Firmware or Power Failure" hypothesis,
        # which maps to the honest unknown_kernel_firmware_power tag.
        assert incidents[0]["mechanism_tags"] == ["unknown_kernel_firmware_power"]

    def test_incident_ids_are_stable_across_two_scans_of_the_same_data(self):
        from collector import analyse, build_incidents

        def check(title, output):
            return {"title": title, "output": output, "category": "Software", "status": "ok",
                    "returncode": 0, "duration_seconds": 0, "command": "test"}

        checks = {
            "boot_history": check("boot", "reboot   system boot  7.1.5-200.fc44.x Wed Jul 29 12:26 - crash  (03:25)"),
            "journal_boots": check("boots", "-1 e2110b7c6f7e4e72afca6dfe736dbfb8 Wed 2026-07-29 12:26:00 AEST Wed 2026-07-29 13:26:00 AEST\n0 e2110b7c6f7e4e72afca6dfe736dbfb8 Wed 2026-07-29 13:26:00 AEST Wed 2026-07-29 13:26:00 AEST"),
        }
        findings, _ = analyse(checks)
        first_run, _, _ = build_incidents(findings, checks)
        second_run, _, _ = build_incidents(findings, checks)
        assert first_run[0]["incident_id"] == second_run[0]["incident_id"]
