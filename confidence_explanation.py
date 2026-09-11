"""Explainable confidence: turn collector.py's existing ranked hypotheses,
plus incident_model's failure_scope/evidence_completeness and
incident_fingerprint's family data, into the structured explanation shape
a person actually needs -- supporting evidence, counter-evidence, missing
evidence, competing hypotheses, confidence, and what observation or test
would move the needle -- instead of a bare score.

This does not replace or re-run collector.py's hypothesis ranking
(title/category/score/confidence/supports/against/next_test); it only
explains it. The ranking/scoring rules themselves live in collector.py and
are out of scope here.
"""
from __future__ import annotations

from typing import Any

# Small, honest, mechanism-specific templates for "what would move this
# hypothesis". Deliberately generic rather than pretending to know exactly
# what evidence exists for a specific incident beyond what's already
# tracked -- these are suggestions of evidence classes to look for, not
# predictions of what they'll show.
_MECHANISM_STRENGTHEN_WEAKEN: dict[str, tuple[str, str]] = {
    "gpu_drm": (
        "A GPU/DRM coredump, dmesg GPU reset trace, or symbolic backtrace pointing at the "
        "graphics stack in this same window would strengthen it.",
        "A recurrence of this failure signature with no graphics/DRM evidence at all would weaken it.",
    ),
    "memory_pressure": (
        "Memory/swap/zram PSI samples or a top-RSS-process snapshot from immediately before this "
        "incident showing genuine exhaustion would strengthen it.",
        "A recurrence of this failure signature with memory/swap utilisation staying low throughout "
        "would weaken it.",
    ),
    "storage_filesystem": (
        "SMART/NVMe error counters, dmesg I/O errors, or D-state (blocked) process evidence in this "
        "window would strengthen it.",
        "A recurrence of this failure signature with no storage/filesystem errors logged would "
        "weaken it.",
    ),
    "thermal": (
        "Sensor temperature samples showing a critical/throttling reading immediately before this "
        "incident would strengthen it.",
        "A recurrence of this failure signature with normal temperatures throughout would weaken it.",
    ),
    "hardware_ras": (
        "An uncorrectable (as opposed to correctable) PCIe/RAS error, or a repeat on the same "
        "device, would strengthen it.",
        "No further errors from the same device across several subsequent boots would weaken it.",
    ),
    "unknown_kernel_firmware_power": (
        "A kdump/netconsole capture of an actual kernel panic, or a firmware/BIOS log entry, during "
        "a future occurrence would strengthen and sharpen this hypothesis.",
        "A future occurrence that instead shows a clear alternative mechanism (memory, storage, "
        "graphics) would weaken this catch-all explanation in favour of that one.",
    ),
    "application_fault": (
        "A symbolic backtrace for the crashing process pointing at a specific, reproducible code path "
        "would strengthen it.",
        "The same crash signature occurring with no corresponding coredump or process-level evidence "
        "would weaken it.",
    ),
}

_EVIDENCE_GAP_MESSAGES: dict[str, str] = {
    "journal": "No journal evidence was found in this incident's own time window.",
    "coredump": "No coredump evidence was found in this incident's own time window.",
    "canary_telemetry": "Canary/heartbeat telemetry has not been joined into this incident yet.",
    "desktop_heartbeat": "Desktop-heartbeat samples have not been joined into this incident yet.",
    "user_observations": "No user-reported observations ('what did you see?') have been recorded for this incident yet.",
}


def _missing_evidence(incident: dict[str, Any]) -> list[str]:
    completeness = incident.get("evidence_completeness") or {}
    missing = []
    for source, state in completeness.items():
        if state not in ("complete", "partial"):
            missing.append(_EVIDENCE_GAP_MESSAGES.get(source, f"{source}: {state}"))
    return missing


def explain_hypothesis(
    incident: dict[str, Any],
    hypothesis: dict[str, Any],
    rank: int,
    all_hypotheses: list[dict[str, Any]] | None = None,
    family: Any | None = None,
) -> dict[str, Any]:
    """Structured explanation for one of an incident's existing,
    already-ranked hypotheses. `family` is an optional
    incident_fingerprint.IncidentFamily for recurrence context."""
    all_hypotheses = all_hypotheses if all_hypotheses is not None else incident.get("hypotheses", [])
    competing = [h["title"] for i, h in enumerate(all_hypotheses) if i != rank]

    mechanism_tags = incident.get("mechanism_tags") or []
    tag = mechanism_tags[rank] if rank < len(mechanism_tags) else "unknown"
    strengthen, weaken = _MECHANISM_STRENGTHEN_WEAKEN.get(
        tag, ("More corroborating evidence for this specific mechanism would strengthen it.",
              "A recurrence without any evidence for this mechanism would weaken it.")
    )

    missing = _missing_evidence(incident)
    if missing:
        strengthen = strengthen + " " + missing[0].rstrip(".") + ", if recorded, may also help."

    recurrence_context = None
    if family is not None:
        recurrence_context = (
            f"This failure pattern (failure_scope={family.failure_scope}, "
            f"mechanisms={', '.join(family.dominant_mechanisms)}) has occurred {family.count} time(s), "
            f"first seen {family.first_seen}, last seen {family.last_seen}."
        )

    return {
        "mechanism": hypothesis.get("title"),
        "category": hypothesis.get("category"),
        "rank": rank,
        "confidence": hypothesis.get("confidence"),
        "supporting_evidence": list(hypothesis.get("supports", [])),
        "counter_evidence": list(hypothesis.get("against", [])),
        "missing_evidence": missing,
        "competing_hypotheses": competing,
        "recurrence_context": recurrence_context,
        "what_would_strengthen": strengthen,
        "what_would_weaken": weaken,
        "best_next_test": hypothesis.get("next_test"),
    }


def explain_incident(incident: dict[str, Any], family: Any | None = None) -> list[dict[str, Any]]:
    """Explanation for every hypothesis on this incident, ranked order
    preserved (index 0 is collector.py's leading hypothesis)."""
    hypotheses = incident.get("hypotheses", [])
    return [
        explain_hypothesis(incident, h, rank, all_hypotheses=hypotheses, family=family)
        for rank, h in enumerate(hypotheses)
    ]


def format_explanation_text(explanation: dict[str, Any]) -> str:
    """Render one hypothesis explanation as the plain-language block shape
    from the mission brief (Likely mechanism / Confidence / Supports /
    Against / Missing / Next useful evidence)."""
    lines = [
        f"Likely mechanism: {explanation['mechanism']}",
        f"Confidence: {explanation['confidence']}",
        "",
    ]
    if explanation["supporting_evidence"]:
        lines.append("Supports:")
        lines.extend(f"- {item}" for item in explanation["supporting_evidence"])
        lines.append("")
    if explanation["counter_evidence"]:
        lines.append("Against:")
        lines.extend(f"- {item}" for item in explanation["counter_evidence"])
        lines.append("")
    if explanation["missing_evidence"]:
        lines.append("Missing:")
        lines.extend(f"- {item}" for item in explanation["missing_evidence"])
        lines.append("")
    if explanation["competing_hypotheses"]:
        lines.append("Competing hypotheses:")
        lines.extend(f"- {item}" for item in explanation["competing_hypotheses"])
        lines.append("")
    if explanation["recurrence_context"]:
        lines.append(f"Recurrence: {explanation['recurrence_context']}")
        lines.append("")
    lines.append(f"Next useful evidence: {explanation['best_next_test']}")
    return "\n".join(lines)
