"""Cross-scan incident history.

incident_fingerprint.build_families() can only find recurring patterns
across the incidents it's actually given -- a single scan typically only
covers the current and previous boot, so real recurrence tracking needs
incidents from *previously saved* scans too. This module reads those
previously-saved scan reports; it never writes, deletes, or otherwise
manages the directory they live in, and it deliberately does not run
inside the privileged broker (privileged_helper.py) -- family/recurrence
computation stays entirely in the unprivileged process that already has
ordinary access to the user's own saved reports, so this adds no new
privileged attack surface.

Bounded by design: only the most recent MAX_HISTORY_FILES scan files are
read, and any single file larger than MAX_FILE_SIZE_BYTES is skipped, so a
large or adversarially huge Documents folder can't make every scan slow or
exhaust memory.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

MAX_HISTORY_FILES = 200
MAX_FILE_SIZE_BYTES = 20 * 1024 * 1024


def load_incident_history(report_dir: Path, *, exclude_generated: str | None = None) -> list[dict[str, Any]]:
    """All incidents found across the most recent scan-*.json files in
    report_dir, oldest-first by file mtime. Malformed, unreadable, or
    oversized files are skipped, never fatal -- history is a convenience
    layer, not something the rest of the app depends on to function.

    `exclude_generated`, if given, skips any file whose metadata.generated
    matches it, so the scan currently being processed isn't double-counted
    if it has already been saved into report_dir.
    """
    if not report_dir.exists():
        return []

    paths = sorted(report_dir.glob("scan-*.json"), key=lambda p: p.stat().st_mtime)[-MAX_HISTORY_FILES:]
    incidents: list[dict[str, Any]] = []
    for path in paths:
        try:
            if path.stat().st_size > MAX_FILE_SIZE_BYTES:
                continue
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        if exclude_generated and data.get("metadata", {}).get("generated") == exclude_generated:
            continue
        incidents.extend(data.get("incidents", []) or [])
    return incidents


def families_from_history(
    report_dir: Path,
    current_incidents: list[dict[str, Any]] | None = None,
    *,
    exclude_generated: str | None = None,
):
    """Build recurrence families from all incident history in report_dir,
    combined with `current_incidents` from a scan not yet saved there."""
    from incident_fingerprint import build_families

    history = load_incident_history(report_dir, exclude_generated=exclude_generated)
    combined = history + list(current_incidents or [])
    return build_families(combined)


def family_for_incident(families, incident: dict[str, Any]):
    """The IncidentFamily in `families` that matches `incident`'s own
    fingerprint, or None if no family was built for it (e.g. `families`
    was computed without `incident` included)."""
    from incident_fingerprint import compute_fingerprint

    fingerprint = compute_fingerprint(incident)
    for family in families:
        if family.fingerprint == fingerprint:
            return family
    return None
