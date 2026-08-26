#!/usr/bin/env python3
import sys
import unittest
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import host_stability_audit as audit


class HostStabilityAuditTests(unittest.TestCase):
    def test_parse_swapon(self):
        rows = audit.parse_swapon("NAME TYPE SIZE USED PRIO\n/dev/zram0 partition 8589934592 0 100\n")
        self.assertEqual(rows, [{"name": "/dev/zram0", "type": "partition", "size": "8589934592", "used": "0", "priority": "100"}])

    def test_issue_shape(self):
        item = audit.issue("memory", "systemd-oomd is active", "confirmed protection", ["active"], "keep it enabled")
        self.assertEqual(item["category"], "memory")
        self.assertEqual(item["status"], "confirmed protection")
        self.assertIn("recommended_action", item)

    def test_render_markdown_contains_classifications(self):
        data = {
            "generated": "2026-08-26T00:00:00+10:00",
            "host": {"hostname": "host", "kernel": "kernel", "cmdline_relevant": "", "session": ""},
            "issues": [audit.issue("graphics", "i915 atomic update failures", "confirmed problem", ["line"], "update")],
            "not_supported_by_current_evidence": ["random kernel parameters"],
        }
        text = audit.render_markdown(data)
        self.assertIn("i915 atomic update failures", text)
        self.assertIn("confirmed problem", text)
        self.assertIn("random kernel parameters", text)

    @patch("host_stability_audit.run")
    @patch("host_stability_audit.service_state")
    @patch("host_stability_audit.read")
    @patch("pathlib.Path.exists")
    def test_oomd_active_but_no_monitored_cgroups(self, mock_exists, mock_read, mock_service_state, mock_run):
        mock_exists.return_value = True
        mock_read.return_value = "1"

        def fake_run(argv, timeout=20):
            if argv[0] == "oomctl":
                return {"status": "ok", "returncode": 0, "output": "Random preceding text mentioning app.slice\nSwap Monitored CGroups:\nMemory Pressure Monitored CGroups:\n\tPath: /system.slice\n\tPath: /app.slice"}
            return {"status": "ok", "returncode": 0, "output": ""}

        def fake_service_state(name):
            if name == "systemd-oomd.service":
                return {"active": "active", "enabled": "enabled"}
            return {"active": "active", "enabled": "enabled"}

        mock_run.side_effect = fake_run
        mock_service_state.side_effect = fake_service_state

        data = audit.audit()
        oomd_issue = next(i for i in data["issues"] if i["category"] == "memory" and "systemd-oomd" in i["title"])
        self.assertEqual(oomd_issue["title"], "systemd-oomd is active but workload protection is incomplete")
        self.assertEqual(oomd_issue["status"], "partial protection")
        # Ensure swap isn't falsely marked true because app.slice appears in preceding text or pressure section
        self.assertTrue(any("app.slice swap monitored: False" in line for line in oomd_issue["evidence"]))

    @patch("host_stability_audit.run")
    @patch("host_stability_audit.service_state")
    @patch("host_stability_audit.read")
    @patch("pathlib.Path.exists")
    def test_oomd_active_custom_limits_accepted(self, mock_exists, mock_read, mock_service_state, mock_run):
        mock_exists.return_value = True
        mock_read.return_value = "1"

        def fake_run(argv, timeout=20):
            if argv[0] == "oomctl":
                return {"status": "ok", "returncode": 0, "output": "Swap Monitored CGroups:\n\tPath: /app.slice\n\tPath: /background.slice\nMemory Pressure Monitored CGroups:\n\tPath: /app.slice\n\t\tMemory Pressure Limit: 50.00%\n\tPath: /background.slice\n\t\tMemory Pressure Limit: 80.00%"}
            return {"status": "ok", "returncode": 0, "output": ""}

        def fake_service_state(name):
            if name == "systemd-oomd.service":
                return {"active": "active", "enabled": "enabled"}
            return {"active": "active", "enabled": "enabled"}

        mock_run.side_effect = fake_run
        mock_service_state.side_effect = fake_service_state

        data = audit.audit()
        oomd_issue = next(i for i in data["issues"] if i["category"] == "memory" and "systemd-oomd" in i["title"])
        self.assertEqual(oomd_issue["title"], "systemd-oomd is active and monitoring workloads")
        self.assertTrue(any("limit: 80.00%" in line for line in oomd_issue["evidence"]))

    @patch("host_stability_audit.run")
    @patch("host_stability_audit.service_state")
    @patch("host_stability_audit.read")
    @patch("pathlib.Path.exists")
    def test_oomd_active_missing_monitoring(self, mock_exists, mock_read, mock_service_state, mock_run):
        mock_exists.return_value = True
        mock_read.return_value = "1"

        def fake_run(argv, timeout=20):
            if argv[0] == "oomctl":
                return {"status": "ok", "returncode": 0, "output": "Swap Monitored CGroups:\n\tPath: /app.slice\nMemory Pressure Monitored CGroups:\n\tPath: /app.slice\n\t\tMemory Pressure Limit: 50.00%"}
            return {"status": "ok", "returncode": 0, "output": ""}

        def fake_service_state(name):
            if name == "systemd-oomd.service":
                return {"active": "active", "enabled": "enabled"}
            return {"active": "active", "enabled": "enabled"}

        mock_run.side_effect = fake_run
        mock_service_state.side_effect = fake_service_state

        data = audit.audit()
        oomd_issue = next(i for i in data["issues"] if i["category"] == "memory" and "systemd-oomd" in i["title"])
        self.assertEqual(oomd_issue["title"], "systemd-oomd is active but workload protection is incomplete")
        self.assertEqual(oomd_issue["status"], "partial protection")
        self.assertTrue(any("background.slice swap monitored: False" in line for line in oomd_issue["evidence"]))


    @patch("host_stability_audit.run")
    @patch("host_stability_audit.service_state")
    @patch("host_stability_audit.read")
    @patch("pathlib.Path.exists")
    def test_oomd_active_and_monitored_cgroups(self, mock_exists, mock_read, mock_service_state, mock_run):
        mock_exists.return_value = True
        mock_read.return_value = "1"

        def fake_run(argv, timeout=20):
            if argv[0] == "oomctl":
                return {"status": "ok", "returncode": 0, "output": "Swap Monitored CGroups:\n\tPath: /app.slice\n\tPath: /background.slice\nMemory Pressure Monitored CGroups:\n\tPath: /app.slice\n\t\tMemory Pressure Limit: 50.00%\n\tPath: /background.slice\n\t\tMemory Pressure Limit: 50.00%"}
            return {"status": "ok", "returncode": 0, "output": ""}

        def fake_service_state(name):
            if name == "systemd-oomd.service":
                return {"active": "active", "enabled": "enabled"}
            return {"active": "active", "enabled": "enabled"}

        mock_run.side_effect = fake_run
        mock_service_state.side_effect = fake_service_state

        data = audit.audit()
        oomd_issue = next(i for i in data["issues"] if i["category"] == "memory" and "systemd-oomd" in i["title"])
        self.assertEqual(oomd_issue["title"], "systemd-oomd is active and monitoring workloads")
        self.assertEqual(oomd_issue["status"], "strong preventative protection configured; effectiveness should be confirmed from future real pressure events.")


if __name__ == "__main__":
    unittest.main()
