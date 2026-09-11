"""Structured Incident identity and classification.

collector.build_incidents() already groups evidence around boot boundaries
and ranks explanatory hypotheses for each one -- that machinery is not
duplicated here. What it doesn't yet provide is a stable identity for each
incident (so the same incident computed on a rescan is recognisably "the
same one", which recurrence/fingerprinting in a later pass will need) or an
answer to "WHAT actually froze?" as one of a fixed set of incident classes,
as opposed to only a ranked list of possible explanations.

attach_incident_identity() adds a small number of keys to an existing
incident dict (incident_id, classification, classification_reasoning,
evidence_sources, evidence_completeness) without removing or renaming any
existing key, so every current consumer (report_schema, the GUI, existing
tests) is unaffected.
"""
from __future__ import annotations

import hashlib
from typing import Any

# What actually froze -- a fixed, closed set of incident classes. An
# incident is classified into exactly one of these, falling back to
# 'insufficient_evidence' rather than guessing when the available evidence
# does not clearly support a more specific class. Never add a class here
# that this module cannot actually justify from real evidence.
INCIDENT_CLASSES = (
    "application_only_crash",
    "plasmashell_panel_failure",
    "kwin_compositor_hang",
    "gpu_drm_i915_incident",
    "system_alive_desktop_dead",
    "memory_thrashing",
    "oom_kill_contained",
    "storage_filesystem_blocking",
    "kernel_hard_lockup",
    "hardware_ras_incident",
    "abrupt_power_loss",
    "clean_reboot_shutdown",
    "insufficient_evidence",
)

_GRAPHICS_SYMPTOM_IDS = {"intel_display", "other_gpu"}
_STORAGE_SYMPTOM_PREFIX = "storage_"
_THERMAL_SYMPTOM_PREFIX = "thermal"


def compute_incident_id(boot_id: str, incident_start: str, failure_boundary: str) -> str:
    """A stable identifier derived from the incident's own content, not
    randomness or wall-clock time, so recomputing the same incident (e.g. on
    a rescan) yields the same id instead of a fresh one each time."""
    digest = hashlib.sha256(f"{boot_id}|{incident_start}|{failure_boundary}".encode()).hexdigest()
    return f"inc_{digest[:16]}"


def _symptom_ids(incident: dict[str, Any]) -> set[str]:
    return {
        e["finding"]["id"]
        for e in incident.get("incident_evidence", [])
        if isinstance(e, dict) and isinstance(e.get("finding"), dict) and e["finding"].get("id")
    }


def _coredump_executables(incident: dict[str, Any]) -> set[str]:
    names = set()
    for c in incident.get("coredumps", []) or []:
        exe = (c or {}).get("executable")
        if exe:
            names.add(str(exe).rsplit("/", 1)[-1].lower())
    return names


def classify_incident(incident: dict[str, Any]) -> tuple[str, list[str]]:
    """Classify one incident dict (as produced by collector.build_incidents)
    into an INCIDENT_CLASSES value, with the reasoning that led there.

    This only uses evidence already present on the incident dict (failure
    boundary, evidence findings, coredumps). It does not have access to
    canary/heartbeat telemetry or user observations yet -- a future pass
    that joins those in can sharpen classes like system_alive_desktop_dead
    that cannot be confidently distinguished from the evidence available
    today. Never manufactures certainty: ambiguous or absent evidence
    produces 'insufficient_evidence' rather than a guess.
    """
    boundary = incident.get("failure_boundary")
    symptoms = _symptom_ids(incident)
    coredump_exes = _coredump_executables(incident)

    if boundary == "kernel panic":
        return "kernel_hard_lockup", ["Boot boundary was a logged kernel panic."]
    if boundary == "watchdog lockup":
        return "kernel_hard_lockup", ["Boot boundary was a hardware/software watchdog-triggered lockup."]
    if boundary == "compositor crash":
        return "kwin_compositor_hang", ["Boot boundary was a Wayland/KWin compositor crash."]
    if boundary == "clean shutdown":
        return "clean_reboot_shutdown", ["Boot boundary was a clean, orderly shutdown/reboot sequence."]
    if boundary == "OOM event":
        return "oom_kill_contained", [
            "An OOM kill was logged, and the boot boundary itself was not an unclean shutdown, "
            "so the kernel's OOM killer appears to have contained the pressure rather than the "
            "whole system going down."
        ]

    if "plasmashell" in coredump_exes:
        return "plasmashell_panel_failure", ["A coredump for plasmashell was recorded in this window."]
    if coredump_exes and not symptoms:
        return "application_only_crash", [
            f"Coredump(s) recorded for {', '.join(sorted(coredump_exes))} with no other "
            "system-level symptom evidence in this window."
        ]

    if symptoms & _GRAPHICS_SYMPTOM_IDS:
        return "gpu_drm_i915_incident", ["Intel display/DRM or other GPU error evidence was recorded in this window."]
    if "wayland" in symptoms:
        return "kwin_compositor_hang", ["Wayland/KWin compositor error evidence was recorded in this window."]
    if any(s.startswith(_STORAGE_SYMPTOM_PREFIX) for s in symptoms):
        return "storage_filesystem_blocking", ["Storage/filesystem error evidence was recorded in this window."]
    if "oom" in symptoms:
        return "memory_thrashing", ["Memory/OOM-pressure evidence was recorded in this incident window."]
    if any(s.startswith(_THERMAL_SYMPTOM_PREFIX) for s in symptoms) or "repeated_pcie_device" in symptoms:
        return "hardware_ras_incident", ["Thermal or PCIe hardware-error evidence was recorded in this window."]

    if boundary == "unclean shutdown":
        return "insufficient_evidence", [
            "The boot ended uncleanly (an abrupt whole-machine stop is confirmed), but no "
            "corroborating symptom evidence (memory, graphics, storage, thermal) was found to "
            "identify a specific mechanism, so the cause -- including power loss -- is not "
            "established, only the fact that the machine stopped abruptly."
        ]

    return "insufficient_evidence", ["No evidence pattern in this window matched a known incident class."]


def attach_incident_identity(incident: dict[str, Any]) -> dict[str, Any]:
    """Mutate `incident` in place, adding incident_id/classification/
    classification_reasoning/evidence_sources/evidence_completeness, and
    also return it for convenient chaining."""
    incident["incident_id"] = compute_incident_id(
        incident.get("boot_id", "unknown"),
        incident.get("incident_start", ""),
        incident.get("failure_boundary", ""),
    )
    incident_class, reasoning = classify_incident(incident)
    incident["classification"] = incident_class
    incident["classification_reasoning"] = reasoning

    sources = []
    if incident.get("incident_evidence"):
        sources.append("journal")
    if incident.get("coredumps"):
        sources.append("coredump")
    incident["evidence_sources"] = sources
    # Canary/heartbeat telemetry and user-reported observations are not
    # joined into incidents yet (later mission sections); recorded as an
    # explicit gap rather than silently treating their absence as "healthy".
    incident["evidence_completeness"] = {
        "journal": "journal" in sources,
        "coredump": "coredump" in sources,
        "canary_telemetry": False,
        "desktop_heartbeat": False,
        "user_observations": False,
    }
    return incident
