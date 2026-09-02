import json
from datetime import datetime, timezone
import pytest
from app_crash_doctor import analyze_app_crashes

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

