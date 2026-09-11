"""Incident fingerprinting and recurrence tracking.

A fingerprint groups incidents that share the same recurring failure
PATTERN -- not the same specific occurrence. It is deliberately built only
from incident_model's failure_scope and the leading mechanism_tags (both
already stable, evidence-derived classifications), never from timestamps,
PIDs, boot ids, or any other per-occurrence detail. That means harmless
variation across boots (a different PID, a slightly different timestamp)
never fragments one real recurring problem into separate families, while a
materially different failure_scope or mechanism correctly starts a new
family instead of being silently merged into an unrelated one.

Family/fingerprint identity is kept completely separate from an
individual incident's own incident_id (see incident_model) -- a family
just groups a list of those ids, it never replaces them.
"""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

# How many of an incident's ranked mechanism_tags participate in its
# fingerprint. Deeper than this and two occurrences of "really the same
# problem" with a minor, lower-ranked secondary hypothesis difference
# would incorrectly split into separate families; shallower and
# meaningfully different problems that happen to share a leading mechanism
# would incorrectly merge.
FINGERPRINT_MECHANISM_DEPTH = 2


def compute_fingerprint(incident: dict[str, Any], *, mechanism_depth: int = FINGERPRINT_MECHANISM_DEPTH) -> str:
    scope = incident.get("failure_scope", "unknown")
    tags = tuple(incident.get("mechanism_tags", [])[:mechanism_depth])
    digest = hashlib.sha256(f"{scope}|{'|'.join(tags)}".encode()).hexdigest()
    return f"fam_{digest[:16]}"


@dataclass
class IncidentFamily:
    fingerprint: str
    failure_scope: str
    dominant_mechanisms: list[str]
    incident_ids: list[str] = field(default_factory=list)
    anchors: list[str] = field(default_factory=list)  # incident_anchor_ts, oldest-first
    confidence_trend: list[str] = field(default_factory=list)  # each incident's top confidence, oldest-first
    count: int = 0

    @property
    def first_seen(self) -> str | None:
        return self.anchors[0] if self.anchors else None

    @property
    def last_seen(self) -> str | None:
        return self.anchors[-1] if self.anchors else None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["first_seen"] = self.first_seen
        d["last_seen"] = self.last_seen
        return d


def build_families(incidents: list[dict[str, Any]]) -> list[IncidentFamily]:
    """Group `incidents` (any order; sorted internally by anchor) into
    IncidentFamily records, most-recurring first."""

    def anchor_of(incident: dict[str, Any]) -> str:
        return incident.get("incident_anchor_ts") or incident.get("incident_start") or ""

    families: dict[str, IncidentFamily] = {}
    for incident in sorted(incidents, key=anchor_of):
        fingerprint = compute_fingerprint(incident)
        family = families.get(fingerprint)
        if family is None:
            family = IncidentFamily(
                fingerprint=fingerprint,
                failure_scope=incident.get("failure_scope", "unknown"),
                dominant_mechanisms=list(incident.get("mechanism_tags", []))[:FINGERPRINT_MECHANISM_DEPTH],
            )
            families[fingerprint] = family
        family.incident_ids.append(incident.get("incident_id", "unknown"))
        family.anchors.append(anchor_of(incident))
        family.confidence_trend.append(incident.get("confidence", "low"))
        family.count += 1

    return sorted(families.values(), key=lambda f: f.count, reverse=True)


def frequency_trend(family: IncidentFamily) -> str:
    """'increasing' / 'decreasing' / 'stable' / 'insufficient_data'.

    Compares the average gap between occurrences in the earlier half of
    the family's history against the later half. Needs at least 4
    dated occurrences to say anything; with fewer, honestly reports
    insufficient_data rather than a trend from noise.
    """
    try:
        anchors = sorted(datetime.fromisoformat(a) for a in family.anchors if a)
    except ValueError:
        return "insufficient_data"
    if len(anchors) < 4:
        return "insufficient_data"

    def avg_gap(ts_list: list[datetime]) -> float | None:
        gaps = [(b - a).total_seconds() for a, b in zip(ts_list, ts_list[1:])]
        return (sum(gaps) / len(gaps)) if gaps else None

    mid = len(anchors) // 2
    earlier_gap = avg_gap(anchors[: mid + 1])
    later_gap = avg_gap(anchors[mid:])
    if not earlier_gap or later_gap is None:
        return "insufficient_data"

    ratio = later_gap / earlier_gap
    if ratio < 0.7:
        return "increasing"
    if ratio > 1.3:
        return "decreasing"
    return "stable"


def dormancy_note(family: IncidentFamily, now: datetime) -> str | None:
    """A conservative, explicitly-hedged note when a family hasn't
    recurred in noticeably longer than its own historical gap -- never
    phrased as proof the underlying issue is fixed (a mitigation, an
    unrelated change, or simple chance can equally explain a quiet spell).
    Returns None when there isn't enough history to say anything.
    """
    try:
        anchors = sorted(datetime.fromisoformat(a) for a in family.anchors if a)
    except ValueError:
        return None
    if len(anchors) < 3:
        return None

    gaps = [(b - a).total_seconds() for a, b in zip(anchors, anchors[1:])]
    avg_gap = sum(gaps) / len(gaps)
    since_last = (now - anchors[-1]).total_seconds()
    if avg_gap <= 0 or since_last < avg_gap * 3:
        return None

    days_since = since_last / 86400
    avg_days = avg_gap / 86400
    return (
        f"No matching incident in this family for {days_since:.1f} days, longer than the "
        f"typical {avg_days:.1f}-day gap between occurrences. This does not confirm the "
        "underlying issue is resolved -- track a specific change with the diagnostic "
        "experiment log to say that with more confidence."
    )
