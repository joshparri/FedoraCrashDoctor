#!/usr/bin/env python3
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from collector import build_tasks


class ScanModeTests(unittest.TestCase):
    def test_full_scan_excludes_deep_rpm_verification(self):
        full_keys = {task.key for task in build_tasks("full")}
        deep_keys = {task.key for task in build_tasks("deep")}
        self.assertNotIn("rpm_verify", full_keys)
        self.assertNotIn("fwts", full_keys)
        self.assertIn("rpm_verify", deep_keys)

    def test_invalid_scan_mode_fails(self):
        with self.assertRaises(ValueError):
            build_tasks("maintenance")


if __name__ == "__main__":
    unittest.main()
