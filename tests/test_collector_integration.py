import pytest
import collector
import shutil


def test_collector_includes_normalized_coredumps_in_report(monkeypatch):
    import json
    
    # Mock get_systemd_coredumps to return a structured kwin_wayland crash
    def mock_get_coredumps(*args, **kwargs):
        return [{
            "incident_source": "systemd-coredump",
            "boot_id": "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1",
            "timestamp": 1788137700.0,
            "pid": 9999,
            "signal": 11,
            "signal_name": "SIGSEGV",
            "executable": "/usr/bin/kwin_wayland",
            "core_available": True,
            "raw_source_hash": "abc"
        }]
        
    monkeypatch.setattr("coredump_adapter.get_systemd_coredumps", mock_get_coredumps)
    
    # Mock runner and boots to create a clean environment
    class MockRunner:
        def __init__(self, *args, **kwargs):
            self.cancelled = False
        def execute(self):
            return {
                "journal_boots": {"output": " 0 b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1 Mon 2026-08-31 10:00:00 AEST—Mon 2026-08-31 11:00:00 AEST"}
            }
            
    monkeypatch.setattr("collector.CheckRunner", MockRunner)
    
    # Mock validate_report so we don't need a full valid report schema
    monkeypatch.setattr("collector.validate_report", lambda x: None)
    
    report = collector.collect("quick")
    incidents = report.get("incidents", [])
    
    # We should have an active session incident for boot 0 (b1) 
    assert len(incidents) >= 1
    kwin_incident = next(i for i in incidents if i["boot_id"] == "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1")
    
    # Verify coredump is attached to the incident
    assert "coredumps" in kwin_incident
    assert len(kwin_incident["coredumps"]) == 1
    core = kwin_incident["coredumps"][0]
    
    assert core["pid"] == 9999
    assert core["executable"] == "/usr/bin/kwin_wayland"
    assert core["signal"] == 11
    assert core["boot_id"] == "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1"
