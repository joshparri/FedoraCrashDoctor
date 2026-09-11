"""Structured "what did you see?" user observations for an incident.

Machine evidence (journal, coredumps) cannot always tell you whether the
whole machine froze or just the desktop -- only a person who was there can.
This module represents that as structured, provenance-tagged evidence
associated with an incident by incident_id, not as unquestionable fact:
an observation may sharpen incident_model.classify_failure_scope()'s
'unknown' result, but it never overrides scope the logs already
established with hard evidence, and it is never used to prove a mechanism
(the "why" stays collector.py's ranked hypotheses, untouched here).

Every question is optional -- a person answers what they actually noticed.
Each question has three possible answers (yes/no/unknown) plus a fourth,
implicit state: never asked/answered at all (the field is simply None).
"unknown" ("I don't know / didn't check") is a real, distinct answer, not
the same as "no".
"""
from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any, Callable

TRISTATE_VALUES = ("yes", "no", "unknown")

# key -> the question asked, in the order a wizard/CLI should ask them.
OBSERVATION_QUESTIONS: dict[str, str] = {
    "mouse_moved": "Did the mouse pointer still move?",
    "keyboard_worked": "Did keyboard input work (e.g. did Caps Lock/Num Lock respond)?",
    "tty_switch_worked": "Could you switch to another TTY (Ctrl+Alt+F3)?",
    "audio_continued": "Did audio continue playing?",
    "network_reachable": "Could another machine still ping it?",
    "ssh_reachable": "Could you SSH into it from another machine?",
    "windows_still_updating": "Were existing application windows still updating (e.g. a clock or video)?",
    "only_panel_frozen": "Was only the Plasma panel/start menu frozen (other windows fine)?",
    "whole_desktop_frozen": "Was the whole desktop frozen, not just one app/panel?",
    "display_black_or_no_signal": "Did the display go black or lose signal?",
    "spontaneous_reboot": "Did the machine spontaneously reboot on its own?",
    "held_power_button": "Did you hold the power button to force it off?",
    "recovered_on_its_own": "Did it recover on its own without you doing anything?",
}

# Free-text (not yes/no/unknown) fields, also all optional.
FREE_TEXT_FIELDS: dict[str, str] = {
    "approximate_time": "Approximately when did this happen? (free text, e.g. 'around 10pm' or an ISO timestamp)",
    "activity_before": "What were you doing immediately beforehand?",
}


def _new_observation_id() -> str:
    return f"obs_{uuid.uuid4().hex[:16]}"


@dataclass
class IncidentObservation:
    incident_id: str
    observation_id: str = field(default_factory=_new_observation_id)
    recorded_at: float = field(default_factory=time.time)
    provenance: str = "user_reported"
    approximate_time: str | None = None
    activity_before: str | None = None
    notes: str | None = None
    mouse_moved: str | None = None
    keyboard_worked: str | None = None
    tty_switch_worked: str | None = None
    audio_continued: str | None = None
    network_reachable: str | None = None
    ssh_reachable: str | None = None
    windows_still_updating: str | None = None
    only_panel_frozen: str | None = None
    whole_desktop_frozen: str | None = None
    display_black_or_no_signal: str | None = None
    spontaneous_reboot: str | None = None
    held_power_button: str | None = None
    recovered_on_its_own: str | None = None

    def __post_init__(self) -> None:
        for f in fields(self):
            if f.name in OBSERVATION_QUESTIONS:
                value = getattr(self, f.name)
                if value is not None and value not in TRISTATE_VALUES:
                    raise ValueError(f"{f.name} must be one of {TRISTATE_VALUES} or None, got {value!r}")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "IncidentObservation":
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})

    def answered_questions(self) -> dict[str, str]:
        return {k: getattr(self, k) for k in OBSERVATION_QUESTIONS if getattr(self, k) is not None}


def observations_dir() -> Path:
    if os.geteuid() == 0:
        return Path("/var/lib/fedora-crash-doctor/observations")
    xdg_state = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    return Path(xdg_state) / "fedora-crash-doctor" / "observations"


def load_observations(incident_id: str, base_dir: Path | None = None) -> list[IncidentObservation]:
    """Oldest-first. A missing or unreadable file is treated as "no
    observations yet", never an error -- observation storage is a
    convenience layer, not required for the rest of the app to function."""
    base_dir = base_dir or observations_dir()
    path = base_dir / f"{incident_id}.json"
    if not path.exists():
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(raw, list):
        return []
    return [IncidentObservation.from_dict(item) for item in raw if isinstance(item, dict)]


def save_observation(observation: IncidentObservation, base_dir: Path | None = None) -> Path:
    """Append one observation to the incident's observation file.
    Multiple observations may exist for the same incident (e.g. more
    detail remembered later, or a second person's account) -- this never
    overwrites earlier ones."""
    base_dir = base_dir or observations_dir()
    base_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = base_dir / f"{observation.incident_id}.json"
    existing = load_observations(observation.incident_id, base_dir)
    existing.append(observation)
    path.write_text(json.dumps([o.to_dict() for o in existing], indent=2), encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return path


def summarize_observations(observations: list[IncidentObservation]) -> dict[str, Any]:
    """A compact, evidence-not-proof summary. `observations` must be
    oldest-first (as load_observations returns); where more than one
    observation answers the same question, the most recent answer wins --
    a genuine disagreement between two answers is not otherwise resolved or
    hidden, only the fact that one is "latest" is used."""
    latest: dict[str, str] = {}
    for obs in observations:
        latest.update(obs.answered_questions())
    return {
        "answered_count": len(latest),
        "total_questions": len(OBSERVATION_QUESTIONS),
        "answers": latest,
    }


def refine_failure_scope_with_observations(
    failure_scope: str,
    failure_scope_reasoning: list[str],
    observations: list[IncidentObservation],
) -> tuple[str, list[str]]:
    """Let user observations sharpen an 'unknown' failure_scope -- never
    override a scope the logs already established with hard evidence
    (a boot-boundary detection), and never touch mechanism/hypotheses at
    all. Only refines when there is a positive "the system was still
    alive" signal (network/SSH/TTY reachable, or audio continued);
    "the desktop looked frozen" alone, with no alive-signal answered, is
    equally consistent with a full whole-system hang the user had no way
    to check, so it is left as 'unknown' rather than guessed.
    """
    if failure_scope != "unknown":
        return failure_scope, failure_scope_reasoning

    answers = summarize_observations(observations)["answers"]
    if not answers:
        return failure_scope, failure_scope_reasoning

    alive_signal = any(
        answers.get(key) == "yes"
        for key in ("network_reachable", "ssh_reachable", "tty_switch_worked", "audio_continued")
    )
    if not alive_signal:
        return failure_scope, failure_scope_reasoning

    reasoning = list(failure_scope_reasoning)
    if answers.get("only_panel_frozen") == "yes" and answers.get("whole_desktop_frozen") != "yes":
        reasoning.append(
            "User-reported: only the panel/start menu was frozen, with a system-alive signal "
            "confirmed, while other windows/the rest of the desktop were not reported frozen."
        )
        return "plasmashell_panel", reasoning

    if answers.get("whole_desktop_frozen") == "yes":
        reasoning.append(
            "User-reported: the whole desktop was frozen while a system-alive signal "
            "(network/SSH/TTY/audio) was confirmed, consistent with the desktop environment "
            "being unresponsive while the underlying system remained alive."
        )
        return "desktop_environment", reasoning

    return failure_scope, failure_scope_reasoning


def run_observation_cli(
    incident_id: str,
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
) -> IncidentObservation:
    """A small, usable terminal flow for recording one observation --
    deliberately not a GUI wizard. Every question can be skipped (blank
    input); y/n/u map to yes/no/unknown, anything else is treated as a
    skip. input_fn/output_fn are injectable so this is testable without a
    real terminal."""
    output_fn(f"Recording what you observed for incident {incident_id}.")
    output_fn("Answer y/n/u (unknown), or press Enter to skip any question.\n")

    answers: dict[str, str | None] = {}
    for key, question in OBSERVATION_QUESTIONS.items():
        raw = input_fn(f"{question} [y/n/u/skip]: ").strip().lower()
        if raw in ("y", "yes"):
            answers[key] = "yes"
        elif raw in ("n", "no"):
            answers[key] = "no"
        elif raw in ("u", "unknown"):
            answers[key] = "unknown"
        else:
            answers[key] = None

    for key, question in FREE_TEXT_FIELDS.items():
        raw = input_fn(f"{question}: ").strip()
        answers[key] = raw or None

    notes = input_fn("Anything else worth noting?: ").strip()
    answers["notes"] = notes or None

    observation = IncidentObservation(incident_id=incident_id, **answers)
    path = save_observation(observation)
    output_fn(f"\nSaved observation {observation.observation_id} to {path}")
    return observation
