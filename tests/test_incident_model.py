"""Tests for the structured Incident model: classification, identity, and
its wiring into collector.build_incidents().
"""
from __future__ import annotations

import incident_model
from incident_model import (
    INCIDENT_CLASSES,
    attach_incident_identity,
    classify_incident,
    compute_incident_id,
)


def _incident(**overrides):
    base = {
        "boot_id": "boot1",
        "incident_start": "2026-09-10T10:00:00",
        "failure_boundary": "unclean shutdown",
        "incident_evidence": [],
        "coredumps": [],
    }
    base.update(overrides)
    return base


def _evidence(finding_id):
    return {"finding": {"id": finding_id}, "line": "x", "timestamp": "2026-09-10T10:00:00"}


class TestClassifyIncident:
    def test_kernel_panic_boundary(self):
        cls, reasons = classify_incident(_incident(failure_boundary="kernel panic"))
        assert cls == "kernel_hard_lockup"
        assert reasons

    def test_watchdog_boundary(self):
        cls, _ = classify_incident(_incident(failure_boundary="watchdog lockup"))
        assert cls == "kernel_hard_lockup"

    def test_compositor_crash_boundary(self):
        cls, _ = classify_incident(_incident(failure_boundary="compositor crash"))
        assert cls == "kwin_compositor_hang"

    def test_clean_shutdown_boundary(self):
        cls, _ = classify_incident(_incident(failure_boundary="clean shutdown"))
        assert cls == "clean_reboot_shutdown"

    def test_oom_event_boundary(self):
        cls, _ = classify_incident(_incident(failure_boundary="OOM event"))
        assert cls == "oom_kill_contained"

    def test_plasmashell_coredump_takes_priority_over_generic_app_crash(self):
        incident = _incident(failure_boundary="active session",
                              coredumps=[{"executable": "/usr/bin/plasmashell"}])
        cls, reasons = classify_incident(incident)
        assert cls == "plasmashell_panel_failure"
        assert reasons

    def test_generic_app_coredump_with_no_other_symptoms(self):
        incident = _incident(failure_boundary="active session",
                              coredumps=[{"executable": "/usr/bin/some-app"}])
        cls, _ = classify_incident(incident)
        assert cls == "application_only_crash"

    def test_coredump_with_other_symptoms_is_not_treated_as_app_only(self):
        """A coredump alongside e.g. graphics symptom evidence shouldn't be
        called an isolated application crash -- something bigger co-occurred."""
        incident = _incident(
            failure_boundary="unclean shutdown",
            coredumps=[{"executable": "/usr/bin/some-app"}],
            incident_evidence=[_evidence("intel_display")],
        )
        cls, _ = classify_incident(incident)
        assert cls != "application_only_crash"

    def test_intel_display_symptom(self):
        incident = _incident(incident_evidence=[_evidence("intel_display")])
        cls, _ = classify_incident(incident)
        assert cls == "gpu_drm_i915_incident"

    def test_wayland_symptom(self):
        incident = _incident(incident_evidence=[_evidence("wayland")])
        cls, _ = classify_incident(incident)
        assert cls == "kwin_compositor_hang"

    def test_storage_symptom(self):
        incident = _incident(incident_evidence=[_evidence("storage_nvme0n1")])
        cls, _ = classify_incident(incident)
        assert cls == "storage_filesystem_blocking"

    def test_oom_symptom_without_oom_boundary(self):
        incident = _incident(failure_boundary="active session", incident_evidence=[_evidence("oom")])
        cls, _ = classify_incident(incident)
        assert cls == "memory_thrashing"

    def test_thermal_symptom(self):
        incident = _incident(incident_evidence=[_evidence("thermal")])
        cls, _ = classify_incident(incident)
        assert cls == "hardware_ras_incident"

    def test_pcie_symptom(self):
        incident = _incident(failure_boundary="active session",
                              incident_evidence=[_evidence("repeated_pcie_device")])
        cls, _ = classify_incident(incident)
        assert cls == "hardware_ras_incident"

    def test_bare_unclean_shutdown_is_insufficient_evidence_not_a_guess(self):
        """This is the important 'never manufacture certainty' case: an
        unclean shutdown with zero corroborating symptoms must not be
        reported as a confident power-loss/hardware diagnosis."""
        cls, reasons = classify_incident(_incident(failure_boundary="unclean shutdown"))
        assert cls == "insufficient_evidence"
        assert any("abrupt" in r.lower() for r in reasons)

    def test_unrecognised_pattern_is_insufficient_evidence(self):
        cls, _ = classify_incident(_incident(failure_boundary="active session"))
        assert cls == "insufficient_evidence"

    def test_every_class_is_reachable_and_documented(self):
        # Sanity guard: every class this module claims to support should be
        # produced by at least one scenario above -- catches a class being
        # silently dead code.
        produced = {
            classify_incident(_incident(failure_boundary="kernel panic"))[0],
            classify_incident(_incident(failure_boundary="clean shutdown"))[0],
            classify_incident(_incident(failure_boundary="OOM event"))[0],
            classify_incident(_incident(failure_boundary="active session",
                                         coredumps=[{"executable": "/usr/bin/plasmashell"}]))[0],
            classify_incident(_incident(failure_boundary="active session",
                                         coredumps=[{"executable": "/usr/bin/some-app"}]))[0],
            classify_incident(_incident(incident_evidence=[_evidence("intel_display")]))[0],
            classify_incident(_incident(incident_evidence=[_evidence("wayland")]))[0],
            classify_incident(_incident(incident_evidence=[_evidence("storage_nvme0n1")]))[0],
            classify_incident(_incident(failure_boundary="active session",
                                         incident_evidence=[_evidence("oom")]))[0],
            classify_incident(_incident(incident_evidence=[_evidence("thermal")]))[0],
            classify_incident(_incident(failure_boundary="unclean shutdown"))[0],
        }
        untested = set(INCIDENT_CLASSES) - produced - {"abrupt_power_loss", "system_alive_desktop_dead"}
        assert not untested, (
            f"INCIDENT_CLASSES has classes with no covering scenario: {untested}. "
            "abrupt_power_loss and system_alive_desktop_dead are deliberately unreachable "
            "today -- current evidence can never justify them without canary/heartbeat "
            "telemetry, which isn't joined in yet."
        )


class TestIncidentIdentity:
    def test_compute_incident_id_is_stable(self):
        a = compute_incident_id("boot1", "2026-09-10T10:00:00", "unclean shutdown")
        b = compute_incident_id("boot1", "2026-09-10T10:00:00", "unclean shutdown")
        assert a == b

    def test_compute_incident_id_differs_for_different_content(self):
        a = compute_incident_id("boot1", "2026-09-10T10:00:00", "unclean shutdown")
        b = compute_incident_id("boot2", "2026-09-10T10:00:00", "unclean shutdown")
        assert a != b

    def test_attach_incident_identity_adds_expected_keys_without_removing_existing(self):
        incident = _incident(strongest_hypothesis="Unknown")
        result = attach_incident_identity(incident)
        assert result is incident  # mutated and returned, not replaced
        assert incident["strongest_hypothesis"] == "Unknown"  # existing key untouched
        assert incident["incident_id"].startswith("inc_")
        assert incident["classification"] in INCIDENT_CLASSES
        assert isinstance(incident["classification_reasoning"], list) and incident["classification_reasoning"]
        assert incident["evidence_sources"] == []
        assert incident["evidence_completeness"] == {
            "journal": False, "coredump": False,
            "canary_telemetry": False, "desktop_heartbeat": False, "user_observations": False,
        }

    def test_evidence_sources_reflect_what_is_actually_present(self):
        incident = _incident(incident_evidence=[_evidence("oom")], coredumps=[{"executable": "/bin/x"}])
        attach_incident_identity(incident)
        assert set(incident["evidence_sources"]) == {"journal", "coredump"}
        assert incident["evidence_completeness"]["journal"] is True
        assert incident["evidence_completeness"]["coredump"] is True


class TestIncidentModelIntegration:
    """Prove attach_incident_identity is really wired into
    collector.build_incidents(), using the same fixture style as
    tests/test_analysis.py, not just unit-tested in isolation."""

    def test_real_graphics_incident_is_classified_and_identified(self):
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
        assert incidents[0]["classification"] == "gpu_drm_i915_incident"
        assert incidents[0]["incident_id"].startswith("inc_")

    def test_real_bare_unclean_shutdown_is_insufficient_evidence(self):
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
        assert incidents[0]["classification"] == "insufficient_evidence"
