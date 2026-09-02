import json
from datetime import datetime, timezone
import pytest
from app_crash_doctor import analyze_app_crashes

def test_app_crash_doctor_tristate_core(monkeypatch):
    import app_crash_doctor
    
    # Mock parse_systemd_coredump_json to return specific core_available states
    def mock_parse(lines, resolve_packages=False):
        return [
            {"timestamp": 100, "pid": 1, "signal": 11, "executable": "/bin/antigravity", "core_available": "unknown", "boot_id": "b1"},
            {"timestamp": 200, "pid": 2, "signal": 11, "executable": "/bin/antigravity", "core_available": True, "boot_id": "b1"},
            {"timestamp": 300, "pid": 3, "signal": 11, "executable": "/bin/antigravity", "core_available": False, "boot_id": "b1"},
        ]
        
    monkeypatch.setattr(app_crash_doctor, "parse_systemd_coredump_json", mock_parse)
    
    issues = analyze_app_crashes(["dummy"])
    assert len(issues) == 1
    issue = issues[0]
    
    # Check that status wasn't collapsed
    # "Most recent coredump: missing (unknown)" is for the last one (False)
    assert any("Most recent coredump: missing" in ev for ev in issue["evidence"])

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

