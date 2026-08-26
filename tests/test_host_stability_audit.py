#!/usr/bin/env python3
import sys
import unittest
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
            "host": {"hostname": "host", "kernel": "kernel", "cmdline_relevant": ""},
            "issues": [audit.issue("graphics", "i915 atomic update failures", "confirmed problem", ["line"], "update")],
            "not_supported_by_current_evidence": ["random kernel parameters"],
        }
        text = audit.render_markdown(data)
        self.assertIn("i915 atomic update failures", text)
        self.assertIn("confirmed problem", text)
        self.assertIn("random kernel parameters", text)


if __name__ == "__main__":
    unittest.main()
