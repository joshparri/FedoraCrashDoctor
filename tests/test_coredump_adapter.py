import json
import pytest
from coredump_adapter import parse_systemd_coredump_json

def test_parse_systemd_coredump_json():
    # Mock journalctl output for a coredump
    mock_json = json.dumps({
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
    })
    
    # Mock invalid or non-coredump log message
    non_coredump = json.dumps({
        "__REALTIME_TIMESTAMP": "1788303225056930",
        "MESSAGE": "Started systemd-coredump@0.service"
    })
    
    lines = [mock_json, "invalid json", non_coredump]
    
    # Do not resolve packages in the test to avoid rpm dependency/slowness
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
    assert incident["command"] == "/opt/zoom/ZoomWebviewHost --type=utility"
    assert incident["comm"] == "ZoomWebviewHost"
    assert incident["unit"] == "user@1002.service"
    assert incident["hostname"] == "AVANCE-WS7"
    assert incident["storage"]["present"] is True
    assert incident["storage"]["location"] == "/var/lib/systemd/coredump/core.Zoom.zst"
    assert incident["core_available"] is True
    assert incident["metadata_available"] is True
    assert incident["journal_cursor"] == "s=abc;i=123"
    assert "raw_source_hash" in incident
