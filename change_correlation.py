"""Bounded correlation of recent system changes around an incident.

Reuses collector.py's existing "rpm_recent" check (`rpm -qa --last`) --
this module adds no new collection task and never executes a package
operation (install/remove/upgrade/downgrade). It only answers "what
changed recently, and how does its timing relate to the incident", and
deliberately never claims a change caused the incident: timing alone is
correlation, not causation, and is reported using language like "changed
18 hours before the incident", never "this caused the incident".

Kernel command-line changes were on the candidate list for this section,
but there is no existing, reliable historical record of past
/proc/cmdline values to compare against (only the current boot's cmdline
is observable) -- rather than fabricate that capability, the current
cmdline is surfaced as context only, with no change-detection claimed for
it.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any

# Package name prefixes grouped into families relevant to crash diagnosis,
# mirroring collector.py's existing "rpm_kernel_graphics" task filter so
# the same families this module reports on are the ones already being
# collected.
PACKAGE_FAMILIES: dict[str, tuple[str, ...]] = {
    "kernel": ("kernel",),
    "graphics_mesa": ("mesa",),
    "linux_firmware": ("linux-firmware",),
    "desktop_kwin_plasma": ("kwin", "kscreen", "plasma"),
    "audio_stack": ("pipewire", "wireplumber"),
}

_NEVRA_RE = re.compile(r"^(?P<name>.+)-(?P<version>[^-]+)-(?P<release>[^-]+)\.(?P<arch>[^.]+)$")
_RPM_LAST_DATE_FORMAT = "%a %d %b %Y %I:%M:%S %p"


def parse_rpm_last_line(line: str) -> dict[str, Any] | None:
    """Parse one line of `rpm -qa --last` output into
    {package, name, version, release, arch, installed_at}, or None if the
    line doesn't match the expected format (rpm --last has no stable
    machine-readable mode, so this must fail closed on anything
    unexpected rather than guess). installed_at is a naive local
    datetime -- rpm --last's trailing timezone abbreviation (e.g. AEST) is
    not reliably machine-parseable, so it is dropped, consistent with how
    the rest of collector.py already treats journal-derived timestamps as
    naive local time.
    """
    line = line.rstrip("\n")
    if not line.strip():
        return None
    parts = line.split(None, 1)
    if len(parts) != 2:
        return None
    nevra, date_part = parts[0], parts[1].strip()

    match = _NEVRA_RE.match(nevra)
    if not match:
        return None

    date_tokens = date_part.rsplit(" ", 1)
    dt_str = date_tokens[0] if len(date_tokens) == 2 else date_part
    try:
        installed_at = datetime.strptime(dt_str, _RPM_LAST_DATE_FORMAT)
    except ValueError:
        return None

    fields = match.groupdict()
    return {
        "package": nevra,
        "name": fields["name"],
        "version": fields["version"],
        "release": fields["release"],
        "arch": fields["arch"],
        "installed_at": installed_at,
    }


def _family_for(package_name: str) -> str | None:
    lowered = package_name.lower()
    for family, prefixes in PACKAGE_FAMILIES.items():
        if any(lowered == p or lowered.startswith(p + "-") or lowered.startswith(p) for p in prefixes):
            return family
    return None


def _format_gap(delta_seconds: float) -> str:
    delta_seconds = abs(delta_seconds)
    if delta_seconds < 3600:
        return f"{int(delta_seconds // 60)} minutes"
    if delta_seconds < 86400:
        return f"{delta_seconds / 3600:.1f} hours"
    return f"{delta_seconds / 86400:.1f} days"


def correlate_recent_changes(
    rpm_recent_output: str,
    incident_anchor: datetime,
    *,
    lookback_days: float = 14.0,
) -> list[dict[str, Any]]:
    """For each tracked package family, find the most recent change within
    `lookback_days` before `incident_anchor` and report it with an
    explicit, non-causal timing statement. Changes after the incident, or
    outside the lookback window, are not reported -- a change discovered
    two months earlier is not usefully "recent" context for this incident.

    Returns one entry per family that had a qualifying change, sorted by
    how close the change was to the incident (closest first), each with:
    family, package, version, installed_at (isoformat), gap_seconds,
    relationship ("before" or "after"), and a plain-language, deliberately
    non-causal `note`.
    """
    lookback_seconds = lookback_days * 86400
    best_per_family: dict[str, dict[str, Any]] = {}

    for line in rpm_recent_output.splitlines():
        parsed = parse_rpm_last_line(line)
        if not parsed:
            continue
        family = _family_for(parsed["name"])
        if not family:
            continue

        gap_seconds = (incident_anchor - parsed["installed_at"]).total_seconds()
        if gap_seconds < 0 or gap_seconds > lookback_seconds:
            continue  # after the incident, or too far before it to be useful context

        existing = best_per_family.get(family)
        if existing is None or gap_seconds < existing["gap_seconds"]:
            best_per_family[family] = {
                "family": family,
                "package": parsed["package"],
                "version": f"{parsed['version']}-{parsed['release']}",
                "installed_at": parsed["installed_at"].isoformat(),
                "gap_seconds": gap_seconds,
                "relationship": "before",
                "note": (
                    f"{parsed['name']} changed to {parsed['version']}-{parsed['release']} "
                    f"{_format_gap(gap_seconds)} before this incident. Temporal correlation only; "
                    "causality is not established."
                ),
            }

    return sorted(best_per_family.values(), key=lambda entry: entry["gap_seconds"])


def current_kernel_cmdline_context(kernel_cmdline_output: str) -> dict[str, Any]:
    """Surface the current boot's /proc/cmdline as informational context
    only. There is no reliable historical record of past cmdline values
    to diff against, so this explicitly does not claim to detect a
    change -- only collector.py's own kernel_cmdline check output, as-is.
    """
    return {
        "current_cmdline": kernel_cmdline_output.strip(),
        "change_detected": None,
        "note": "No historical kernel command-line record is available to compare against; "
                "this is the current boot's command line only, not a detected change.",
    }
