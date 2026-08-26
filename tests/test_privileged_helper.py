#!/usr/bin/env python3
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import privileged_helper as helper


class PrivilegedHelperSecurityTests(unittest.TestCase):
    def test_unknown_action_fails_closed(self):
        with self.assertRaises(ValueError):
            helper.dispatch({"action": "run_arbitrary_command", "params": {}}, 1000, 1000, "/home/user", "req")

    def test_invalid_scan_mode_rejected_before_collection(self):
        with self.assertRaises(ValueError):
            helper.dispatch({"action": "scan", "params": {"mode": "maintenance"}}, 1000, 1000, "/home/user", "req")

    def test_smart_device_path_validation_rejects_injection(self):
        bad_devices = [
            "/dev/../../etc/passwd",
            "/dev/null;reboot",
            "/dev/sda && reboot",
            "/dev/sda$(reboot)",
            "/tmp/fake-device",
            "/etc/passwd",
        ]
        for device in bad_devices:
            with self.subTest(device=device):
                with self.assertRaises(ValueError):
                    helper.dispatch({"action": "smart_short", "params": {"device": device}}, 1000, 1000, "/home/user", "req")

    def test_smart_short_allows_only_discovered_devices(self):
        with mock.patch.object(helper, "discover_smart_devices", return_value=["/dev/sda"]):
            with mock.patch.object(helper, "command", return_value={"ok": True, "output": "started"}):
                result = helper.dispatch({"action": "smart_short", "params": {"device": "/dev/sda"}}, 1000, 1000, "/home/user", "req")
        self.assertTrue(result["ok"])
        self.assertEqual(result["device"], "/dev/sda")

    def test_save_baseline_uses_uid_directory_and_private_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(helper, "STATE_DIR", Path(tmp)):
                helper.save_baseline(1234, {"schema_version": 1, "ok": True})
                path = Path(tmp) / "baselines" / "1234" / "latest.json"
                self.assertTrue(path.exists())
                self.assertEqual(json.loads(path.read_text())["ok"], True)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)

    def test_save_baseline_replaces_symlink_not_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "outside.json"
            target.write_text("outside")
            base_dir = Path(tmp) / "baselines" / "1234"
            base_dir.mkdir(parents=True)
            os.symlink(target, base_dir / "latest.json")
            with mock.patch.object(helper, "STATE_DIR", Path(tmp)):
                helper.save_baseline(1234, {"safe": True})
            self.assertEqual(target.read_text(), "outside")
            self.assertFalse((base_dir / "latest.json").is_symlink())
            self.assertEqual(json.loads((base_dir / "latest.json").read_text())["safe"], True)

    def test_command_rejects_invalid_executable(self):
        with self.assertRaises(ValueError):
            helper.command(["bad;name"], 1)


if __name__ == "__main__":
    unittest.main()
