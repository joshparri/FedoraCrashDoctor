import json
import pytest
from coredump_adapter import parse_systemd_coredump_json

def test_parse_systemd_coredump_json_valid():
    lines = [json.dumps({
        "__CURSOR": "s=abc;i=123",
        "__REALTIME_TIMESTAMP": "1788303225056929",
        "_BOOT_ID": "594e7700b65a4fc4aa67e2ef20c0313e",
        "COREDUMP_PID": "261492",
        "COREDUMP_UID": "1002",
        "COREDUMP_GID": "1002",
        "COREDUMP_SIGNAL": "6",
        "COREDUMP_SIGNAL_NAME": "SIGABRT",
        "COREDUMP_EXE": "/opt/zoom/ZoomWebviewHost",
        "COREDUMP_CMDLINE": "/opt/zoom/ZoomWebviewHost --type=utility",
        "COREDUMP_COMM": "ZoomWebviewHost",
        "COREDUMP_UNIT": "user@1002.service",
        "_HOSTNAME": "AVANCE-WS7",
        "COREDUMP_FILENAME": "/var/lib/systemd/coredump/core.Zoom.zst"
    })]
    
    incidents = parse_systemd_coredump_json(lines, resolve_packages=False)
    assert len(incidents) == 1
    incident = incidents[0]
    assert incident["incident_source"] == "systemd-coredump"
    assert incident["boot_id"] == "594e7700b65a4fc4aa67e2ef20c0313e"
    assert incident["timestamp"] == 1788303225.056929
    assert incident["pid"] == 261492
    assert incident["uid"] == 1002
    assert incident["gid"] == 1002
    assert incident["signal"] == 6
    assert incident["signal_name"] == "SIGABRT"
    assert incident["executable"] == "/opt/zoom/ZoomWebviewHost"
    assert incident["storage"]["present"] is True
    assert incident["core_available"] == "unknown"

def test_parse_malformed_fields_do_not_abort():
    lines = [
        json.dumps({
            "__REALTIME_TIMESTAMP": "not-a-number",
            "COREDUMP_PID": "bad-pid",
            "COREDUMP_UID": "NaN",
            "COREDUMP_GID": "None",
            "COREDUMP_SIGNAL": "SEGV",
            "COREDUMP_EXE": "/bin/bad",
            "COREDUMP_SIGNAL_NAME": "SIGSEGV"
        }),
        json.dumps({
            "__REALTIME_TIMESTAMP": "1788303225056929",
            "COREDUMP_PID": "1234",
            "COREDUMP_EXE": "/bin/good"
        })
    ]
    
    incidents = parse_systemd_coredump_json(lines, resolve_packages=False)
    assert len(incidents) == 2
    
    bad = incidents[0]
    assert bad["timestamp"] is None
    assert bad["pid"] is None
    assert bad["uid"] is None
    assert bad["gid"] is None
    assert bad["signal"] is None
    assert bad["executable"] == "/bin/bad"
    assert bad["signal_name"] == "SIGSEGV"
    
    good = incidents[1]
    assert good["timestamp"] == 1788303225.056929
    assert good["pid"] == 1234
    assert good["executable"] == "/bin/good"

def test_unrelated_journal_messages_ignored():
    lines = [
        json.dumps({"MESSAGE": "Started process"}),
        "invalid json entirely"
    ]
    assert len(parse_systemd_coredump_json(lines, resolve_packages=False)) == 0

def test_deduplication_different_boots():
    from app_crash_doctor import analyze_app_crashes
    import json
    lines = [
        json.dumps({
            "_BOOT_ID": "boot1",
            "__REALTIME_TIMESTAMP": "1788303225056929",
            "COREDUMP_PID": "1234",
            "COREDUMP_EXE": "/bin/antigravity",
            "COREDUMP_SIGNAL": "11"
        }),
        json.dumps({
            "_BOOT_ID": "boot2",
            "__REALTIME_TIMESTAMP": "1788303225056929", # Same timestamp for worst case collision check
            "COREDUMP_PID": "1234",
            "COREDUMP_EXE": "/bin/antigravity",
            "COREDUMP_SIGNAL": "11"
        })
    ]
    
    issues = analyze_app_crashes(lines)
    # The two crashes have different boot ids, so they should be treated as separate instances
    
    # We check raw evidence appearances
    assert len(issues) == 1
    issue = issues[0]
    evidence = str(issue["evidence"])
    assert "Unique incidents: 2" in evidence
    assert "Raw evidence appearances: 2" in evidence

def test_deduplication_same_boot_same_event():
    from app_crash_doctor import analyze_app_crashes
    import json
    lines = [
        json.dumps({
            "_BOOT_ID": "boot1",
            "__REALTIME_TIMESTAMP": "1788303225056929",
            "COREDUMP_PID": "1234",
            "COREDUMP_EXE": "/bin/antigravity",
            "COREDUMP_SIGNAL": "11"
        }),
        json.dumps({
            "_BOOT_ID": "boot1",
            "__REALTIME_TIMESTAMP": "1788303225056929", 
            "COREDUMP_PID": "1234",
            "COREDUMP_EXE": "/bin/antigravity",
            "COREDUMP_SIGNAL": "11"
        })
    ]
    
    issues = analyze_app_crashes(lines)
    # The two crashes have exactly identical unique properties, should dedup to 1
    
    assert len(issues) == 1
    issue = issues[0]
    evidence = str(issue["evidence"])
    assert "Unique incidents: 1" in evidence
    assert "Raw evidence appearances: 2" in evidence
    
def test_get_systemd_coredumps_respects_limits(monkeypatch):
    import coredump_adapter
    import io
    
    # We mock Popen so we don't actually run journalctl
    class MockPopen:
        def __init__(self, *args, **kwargs):
            lines = [
                json.dumps({"_BOOT_ID": "b1", "COREDUMP_PID": "1" + str(i), "COREDUMP_EXE": "/bin/crash"}) + "\n"
                for i in range(150) # Give it 150 lines
            ]
            self.stdout = io.BytesIO("".join(lines).encode('utf-8'))
            
        def kill(self):
            pass
        def wait(self, timeout):
            pass
            
    monkeypatch.setattr("subprocess.Popen", MockPopen)
    
    # Also mock select.select so it doesn't block on our BytesIO
    monkeypatch.setattr("select.select", lambda r, w, x, t: (r, w, x))
    
    incidents = coredump_adapter.get_systemd_coredumps(max_records=100)
    # Bounding check, should exit after 100 records
    assert len(incidents) == 100
