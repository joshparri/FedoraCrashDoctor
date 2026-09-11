"""Tests for structured "what did you see?" user observations: the
tri-state answer model, persistence, and the conservative failure_scope
refinement rule.
"""
from __future__ import annotations

import pytest

from incident_observations import (
    FREE_TEXT_FIELDS,
    OBSERVATION_QUESTIONS,
    IncidentObservation,
    load_observations,
    refine_failure_scope_with_observations,
    run_observation_cli,
    save_observation,
    summarize_observations,
)


class TestIncidentObservationModel:
    def test_every_field_is_optional(self):
        obs = IncidentObservation(incident_id="inc_x")
        assert obs.answered_questions() == {}

    def test_unknown_is_a_distinct_answer_from_no(self):
        obs = IncidentObservation(incident_id="inc_x", mouse_moved="unknown")
        assert obs.mouse_moved == "unknown"
        assert obs.mouse_moved != "no"

    def test_invalid_tristate_value_rejected(self):
        with pytest.raises(ValueError):
            IncidentObservation(incident_id="inc_x", mouse_moved="maybe")

    def test_provenance_defaults_to_user_reported(self):
        obs = IncidentObservation(incident_id="inc_x")
        assert obs.provenance == "user_reported"

    def test_round_trips_through_dict(self):
        obs = IncidentObservation(incident_id="inc_x", mouse_moved="yes", notes="it was weird")
        restored = IncidentObservation.from_dict(obs.to_dict())
        assert restored == obs

    def test_answered_questions_only_includes_tristate_fields_that_were_set(self):
        obs = IncidentObservation(incident_id="inc_x", mouse_moved="yes", keyboard_worked="no",
                                   notes="free text is not a tristate question")
        assert obs.answered_questions() == {"mouse_moved": "yes", "keyboard_worked": "no"}


class TestPersistence:
    def test_save_and_load_round_trip(self, tmp_path):
        obs = IncidentObservation(incident_id="inc_x", mouse_moved="yes")
        save_observation(obs, base_dir=tmp_path)
        loaded = load_observations("inc_x", base_dir=tmp_path)
        assert len(loaded) == 1
        assert loaded[0].mouse_moved == "yes"

    def test_multiple_observations_for_one_incident_are_appended_not_overwritten(self, tmp_path):
        save_observation(IncidentObservation(incident_id="inc_x", mouse_moved="yes"), base_dir=tmp_path)
        save_observation(IncidentObservation(incident_id="inc_x", audio_continued="no"), base_dir=tmp_path)
        loaded = load_observations("inc_x", base_dir=tmp_path)
        assert len(loaded) == 2

    def test_load_missing_file_returns_empty_list(self, tmp_path):
        assert load_observations("inc_never_recorded", base_dir=tmp_path) == []

    def test_load_malformed_file_returns_empty_list_not_an_error(self, tmp_path):
        tmp_path.mkdir(exist_ok=True)
        (tmp_path / "inc_x.json").write_text("not valid json{")
        assert load_observations("inc_x", base_dir=tmp_path) == []

    def test_saved_file_is_private(self, tmp_path):
        import stat
        path = save_observation(IncidentObservation(incident_id="inc_x"), base_dir=tmp_path)
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


class TestSummarize:
    def test_empty_observations_summary(self):
        summary = summarize_observations([])
        assert summary["answered_count"] == 0
        assert summary["total_questions"] == len(OBSERVATION_QUESTIONS)

    def test_most_recent_answer_wins_for_the_same_question(self):
        older = IncidentObservation(incident_id="inc_x", mouse_moved="yes")
        newer = IncidentObservation(incident_id="inc_x", mouse_moved="no")
        summary = summarize_observations([older, newer])
        assert summary["answers"]["mouse_moved"] == "no"

    def test_answers_from_different_observations_are_merged(self):
        first = IncidentObservation(incident_id="inc_x", mouse_moved="yes")
        second = IncidentObservation(incident_id="inc_x", audio_continued="no")
        summary = summarize_observations([first, second])
        assert summary["answers"] == {"mouse_moved": "yes", "audio_continued": "no"}


class TestRefineFailureScope:
    def test_does_not_override_scope_already_established_from_logs(self):
        """A user's imperfect memory must never override a confirmed
        unclean-shutdown boot boundary."""
        observations = [IncidentObservation(incident_id="inc_x", whole_desktop_frozen="yes",
                                             network_reachable="yes")]
        scope, reasoning = refine_failure_scope_with_observations("whole_system", ["boundary evidence"], observations)
        assert scope == "whole_system"
        assert reasoning == ["boundary evidence"]

    def test_no_observations_leaves_unknown_as_unknown(self):
        scope, _ = refine_failure_scope_with_observations("unknown", ["no evidence"], [])
        assert scope == "unknown"

    def test_frozen_desktop_alone_without_alive_signal_stays_unknown(self):
        """'The desktop looked frozen' with no confirmation the system was
        otherwise alive is equally consistent with a whole-system hang the
        user had no way to check -- must not be guessed."""
        observations = [IncidentObservation(incident_id="inc_x", whole_desktop_frozen="yes")]
        scope, _ = refine_failure_scope_with_observations("unknown", [], observations)
        assert scope == "unknown"

    def test_panel_only_frozen_with_alive_signal_refines_to_plasmashell_panel(self):
        observations = [IncidentObservation(incident_id="inc_x", only_panel_frozen="yes",
                                             whole_desktop_frozen="no", ssh_reachable="yes")]
        scope, reasoning = refine_failure_scope_with_observations("unknown", ["nothing in logs"], observations)
        assert scope == "plasmashell_panel"
        assert len(reasoning) == 2  # original reasoning preserved, new reasoning appended

    def test_whole_desktop_frozen_with_alive_signal_refines_to_desktop_environment(self):
        observations = [IncidentObservation(incident_id="inc_x", whole_desktop_frozen="yes",
                                             network_reachable="yes")]
        scope, _ = refine_failure_scope_with_observations("unknown", [], observations)
        assert scope == "desktop_environment"

    def test_audio_continuing_counts_as_an_alive_signal(self):
        observations = [IncidentObservation(incident_id="inc_x", whole_desktop_frozen="yes",
                                             audio_continued="yes")]
        scope, _ = refine_failure_scope_with_observations("unknown", [], observations)
        assert scope == "desktop_environment"


class TestObservationCli:
    def test_records_answers_and_saves(self, tmp_path, monkeypatch):
        monkeypatch.setattr("incident_observations.observations_dir", lambda: tmp_path)
        responses = iter(
            ["y"] * len(OBSERVATION_QUESTIONS)  # every tristate question answered yes
            + [""] * len(FREE_TEXT_FIELDS)       # free-text fields skipped
            + [""]                               # notes skipped
        )
        outputs = []
        observation = run_observation_cli("inc_x", input_fn=lambda _prompt: next(responses),
                                           output_fn=outputs.append)
        assert observation.incident_id == "inc_x"
        assert all(v == "yes" for v in observation.answered_questions().values())
        assert any("Saved observation" in line for line in outputs)
        assert load_observations("inc_x", base_dir=tmp_path)

    def test_blank_or_junk_answers_are_skipped_not_recorded_as_no(self, tmp_path, monkeypatch):
        monkeypatch.setattr("incident_observations.observations_dir", lambda: tmp_path)
        responses = iter(["", "garbage"] + [""] * (len(OBSERVATION_QUESTIONS) - 2)
                          + [""] * len(FREE_TEXT_FIELDS) + [""])
        observation = run_observation_cli("inc_x", input_fn=lambda _prompt: next(responses), output_fn=lambda _l: None)
        assert observation.answered_questions() == {}

    def test_u_is_recorded_as_unknown_not_skipped(self, tmp_path, monkeypatch):
        monkeypatch.setattr("incident_observations.observations_dir", lambda: tmp_path)
        responses = iter(["u"] + [""] * (len(OBSERVATION_QUESTIONS) - 1)
                          + [""] * len(FREE_TEXT_FIELDS) + [""])
        observation = run_observation_cli("inc_x", input_fn=lambda _prompt: next(responses), output_fn=lambda _l: None)
        first_key = next(iter(OBSERVATION_QUESTIONS))
        assert getattr(observation, first_key) == "unknown"
