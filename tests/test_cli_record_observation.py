"""CLI wiring for `--record-observation`: it must reach
incident_observations.run_observation_cli with the given incident id and
must not require --cli/--scan (it's a standalone lightweight action, like
--version)."""
from __future__ import annotations

import fedora_crash_doctor


def test_record_observation_flag_invokes_the_observation_cli(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "incident_observations.run_observation_cli",
        lambda incident_id, **kwargs: calls.append(incident_id),
    )
    rc = fedora_crash_doctor.main(["--record-observation", "inc_abc123"])
    assert rc == 0
    assert calls == ["inc_abc123"]


def test_record_observation_does_not_require_cli_flag(monkeypatch):
    """Unlike --scan, this should work standalone -- no --cli needed."""
    monkeypatch.setattr("incident_observations.run_observation_cli", lambda incident_id, **kwargs: None)
    rc = fedora_crash_doctor.main(["--record-observation", "inc_xyz"])
    assert rc == 0
