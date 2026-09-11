import json
from datetime import datetime, timezone
import pytest
from app_crash_doctor import analyze_app_crashes, load_min_incident_overrides

def test_app_crash_doctor_tristate_core(monkeypatch):
    import app_crash_doctor
    
    # Mock parse_systemd_coredump_json to return specific core_available states
    def mock_parse(lines, resolve_packages=False):
        return [
            {"timestamp": 100, "pid": 1, "signal": 11, "executable": "/bin/app1", "core_available": "unknown", "boot_id": "b1"},
            {"timestamp": 100, "pid": 2, "signal": 11, "executable": "/bin/app1", "core_available": "unknown", "boot_id": "b1"},
            {"timestamp": 100, "pid": 3, "signal": 11, "executable": "/bin/app1", "core_available": "unknown", "boot_id": "b1"},
            
            {"timestamp": 200, "pid": 4, "signal": 11, "executable": "/bin/app2", "core_available": True, "boot_id": "b1"},
            {"timestamp": 200, "pid": 5, "signal": 11, "executable": "/bin/app2", "core_available": True, "boot_id": "b1"},
            {"timestamp": 200, "pid": 6, "signal": 11, "executable": "/bin/app2", "core_available": True, "boot_id": "b1"},
            
            {"timestamp": 300, "pid": 7, "signal": 11, "executable": "/bin/app3", "core_available": False, "boot_id": "b1"},
            {"timestamp": 300, "pid": 8, "signal": 11, "executable": "/bin/app3", "core_available": False, "boot_id": "b1"},
            {"timestamp": 300, "pid": 9, "signal": 11, "executable": "/bin/app3", "core_available": False, "boot_id": "b1"},
        ]
        
    monkeypatch.setattr(app_crash_doctor, "parse_systemd_coredump_json", mock_parse)
    
    issues = app_crash_doctor.analyze_app_crashes(["dummy"])
    assert len(issues) == 3
    
    issue1 = next(i for i in issues if "App1" in i["title"])
    issue2 = next(i for i in issues if "App2" in i["title"])
    issue3 = next(i for i in issues if "App3" in i["title"])
    
    assert any("Most recent coredump: unknown" in ev for ev in issue1["evidence"])
    assert any("Most recent coredump: present" in ev for ev in issue2["evidence"])
    assert any("Most recent coredump: missing" in ev for ev in issue3["evidence"])

def test_app_crash_doctor_malformed_timestamp():
    lines = [
        json.dumps({
            "COREDUMP_PID": "1", "COREDUMP_EXE": "/bin/time_traveler", "COREDUMP_SIGNAL": "11", "__REALTIME_TIMESTAMP": "invalid"
        }),
        json.dumps({
            "COREDUMP_PID": "2", "COREDUMP_EXE": "/bin/time_traveler", "COREDUMP_SIGNAL": "11", "__REALTIME_TIMESTAMP": "invalid2"
        }),
        json.dumps({
            "COREDUMP_PID": "3", "COREDUMP_EXE": "/bin/time_traveler", "COREDUMP_SIGNAL": "11", "__REALTIME_TIMESTAMP": "invalid3"
        })
    ]
    issues = analyze_app_crashes(lines)
    assert len(issues) == 1
    issue = issues[0]

    # Check that time didn't become "right now"
    # First seen and Last seen should say "Unknown"
    assert "First seen: Unknown" in issue["evidence"]
    assert "Last seen: Unknown" in issue["evidence"]
    assert "Recent/current boot crashes: 0" in issue["evidence"]


def _crash_lines(app_path, count):
    return [
        f"Thu 2026-09-10 10:32:0{i} AEST {100+i} 1002 1002 SIGABRT present {app_path} 19K"
        for i in range(count)
    ]


def test_no_application_gets_special_treatment_by_default(tmp_path, monkeypatch):
    """Fedora Crash Doctor ships with no application-specific defaults: with
    no config file present, every executable uses the same generic
    threshold, regardless of name."""
    monkeypatch.setattr('app_crash_doctor.app_crash_profile_path', lambda: tmp_path / 'missing.json')
    below_threshold = _crash_lines('/opt/antigravity/antigravity', 2)
    issues = analyze_app_crashes(below_threshold)
    assert issues == []


def test_min_incidents_override_is_read_from_external_config(tmp_path, monkeypatch):
    """An executable is only reported below the default threshold if an
    external, user/site-editable config file says so -- never from a
    built-in list baked into the source."""
    config_path = tmp_path / 'app_crash_profiles.json'
    config_path.write_text(json.dumps({
        "executables": {"antigravity": {"min_incidents": 1}},
    }))
    monkeypatch.setattr('app_crash_doctor.app_crash_profile_path', lambda: config_path)

    overrides = load_min_incident_overrides()
    assert overrides == {"antigravity": 1}

    single_crash = _crash_lines('/opt/antigravity/antigravity', 1)
    issues = analyze_app_crashes(single_crash)
    assert len(issues) == 1
    assert "Antigravity" in issues[0]["title"]

    # An unrelated executable with only 1 incident is unaffected by another
    # app's override and still uses the generic default.
    other_app = _crash_lines('/usr/bin/some-other-app', 1)
    assert analyze_app_crashes(other_app) == []


def test_malformed_config_file_does_not_crash_analysis(tmp_path, monkeypatch):
    config_path = tmp_path / 'app_crash_profiles.json'
    config_path.write_text('{not valid json')
    monkeypatch.setattr('app_crash_doctor.app_crash_profile_path', lambda: config_path)

    assert load_min_incident_overrides() == {}
    # Analysis still runs normally with the generic default.
    below_threshold = _crash_lines('/opt/antigravity/antigravity', 2)
    assert analyze_app_crashes(below_threshold) == []

