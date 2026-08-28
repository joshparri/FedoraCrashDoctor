import unittest
from unittest.mock import patch, MagicMock
import json
import os
import subprocess
from pathlib import Path
import tempfile
import sys
from concurrent.futures import ThreadPoolExecutor

# Ensure module can be found
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import plasma_capture

class PlasmaCaptureTests(unittest.TestCase):

    def test_run_helper_timeout(self):
        # We test the real _run function with a timeout
        out = plasma_capture._run(["sleep", "0.1"], timeout=0.01)
        self.assertIn("[TIMEOUT]", out)

    @patch('plasma_capture._run')
    @patch('plasma_capture.subprocess.run')
    @patch('plasma_capture.Path.home')
    def test_capture_creates_unique_dir_and_serializes(self, mock_home, mock_sub_run, mock_run):
        with tempfile.TemporaryDirectory() as tmp:
            mock_home.return_value = Path(tmp)

            # mock get_plasmashell_pid
            mock_run.return_value = "1234"
            mock_sub_run.return_value = MagicMock(stdout="test", returncode=0, stderr="")

            summary = plasma_capture.capture_frozen_plasma()

            capture_path = Path(summary["capture_path"])
            self.assertTrue(capture_path.exists())
            self.assertTrue(capture_path.name.startswith("plasma-freeze-"))

            # Test summary serializes
            summary_json = capture_path / "summary.json"
            self.assertTrue(summary_json.exists())

            with open(summary_json) as f:
                loaded = json.load(f)
                self.assertIn("capture_time", loaded)

    @patch('plasma_capture._run')
    @patch('plasma_capture.subprocess.run')
    @patch('plasma_capture.Path.home')
    def test_pid_zero_handled_safely(self, mock_home, mock_sub_run, mock_run):
        with tempfile.TemporaryDirectory() as tmp:
            mock_home.return_value = Path(tmp)

            def mock_run_side_effect(cmd, *args, **kwargs):
                if cmd == ["systemctl", "--user", "show", "--property=MainPID", "--value", "plasma-plasmashell.service"]:
                    return "0\n"
                return ""

            mock_run.side_effect = mock_run_side_effect
            mock_sub_run.return_value = MagicMock(stdout="", returncode=0, stderr="")

            summary = plasma_capture.capture_frozen_plasma()
            self.assertEqual(summary["plasmashell_pid"], 0)
            self.assertFalse(summary["plasmashell_process_present"])
            self.assertTrue(summary["capture_complete"])

    @patch('plasma_capture._run')
    @patch('plasma_capture.subprocess.run')
    @patch('plasma_capture.Path.home')
    def test_wchan_and_process_state_preserved(self, mock_home, mock_sub_run, mock_run):
        with tempfile.TemporaryDirectory() as tmp:
            mock_home.return_value = Path(tmp)

            def mock_run_side_effect(cmd, *args, **kwargs):
                if cmd == ["systemctl", "--user", "show", "--property=MainPID", "--value", "plasma-plasmashell.service"]:
                    return "1000\n"
                elif cmd[:2] == ["ps", "-p"] and str(cmd).find("stat,wchan") != -1:
                    return "PID PPID STAT WCHAN PCPU PMEM COMM ETIME\n1000 1 Ssl anon_pipe_write 0.0 0.0 plasmashell 00:00"
                return ""

            mock_run.side_effect = mock_run_side_effect
            mock_sub_run.return_value = MagicMock(stdout="", returncode=0, stderr="")

            summary = plasma_capture.capture_frozen_plasma()

            self.assertEqual(summary["plasmashell_stat"], "Ssl")
            self.assertEqual(summary["plasmashell_wchan"], "anon_pipe_write")

            # Ensure no peers were invented
            self.assertNotIn("kwin", str(summary["plasmashell_wchan"]).lower())

    @patch('plasma_capture._run')
    @patch('plasma_capture.subprocess.run')
    @patch('plasma_capture.Path.home')
    def test_dbus_timeout_recorded_correctly(self, mock_home, mock_sub_run, mock_run):
        with tempfile.TemporaryDirectory() as tmp:
            mock_home.return_value = Path(tmp)

            mock_run.return_value = ""
            mock_sub_run.side_effect = subprocess.TimeoutExpired(cmd=["gdbus"], timeout=4.0, output=b"", stderr=b"")

            summary = plasma_capture.capture_frozen_plasma()
            self.assertTrue(summary["dbus_probe_timed_out"])
            self.assertEqual(summary["dbus_probe_exit_code"], -1)
            self.assertEqual(summary["dbus_probe_status"], "timeout")

    @patch('plasma_capture._run')
    @patch('plasma_capture.subprocess.run')
    @patch('plasma_capture.Path.home')
    def test_dbus_healthy_response(self, mock_home, mock_sub_run, mock_run):
        with tempfile.TemporaryDirectory() as tmp:
            mock_home.return_value = Path(tmp)

            mock_run.return_value = ""
            mock_sub_run.return_value = MagicMock(stdout="('PANELS=2',)\n", returncode=0, stderr="")

            summary = plasma_capture.capture_frozen_plasma()
            self.assertFalse(summary["dbus_probe_timed_out"])
            self.assertEqual(summary["dbus_probe_exit_code"], 0)
            self.assertEqual(summary["dbus_probe_status"], "success")

    @patch('plasma_capture._run')
    @patch('plasma_capture.subprocess.run')
    @patch('plasma_capture.Path.home')
    def test_dbus_command_unavailable(self, mock_home, mock_sub_run, mock_run):
        with tempfile.TemporaryDirectory() as tmp:
            mock_home.return_value = Path(tmp)
            mock_run.return_value = ""
            mock_sub_run.side_effect = FileNotFoundError()

            summary = plasma_capture.capture_frozen_plasma()
            self.assertFalse(summary["dbus_probe_timed_out"])
            self.assertEqual(summary["dbus_probe_status"], "command-unavailable")
            self.assertEqual(summary["dbus_probe_stderr"], "gdbus not found")

    @patch('plasma_capture._run')
    @patch('plasma_capture.subprocess.run')
    @patch('plasma_capture.Path.home')
    def test_i915_gpu_hang_atomic_events(self, mock_home, mock_sub_run, mock_run):
        with tempfile.TemporaryDirectory() as tmp:
            mock_home.return_value = Path(tmp)

            def mock_run_side_effect(cmd, *args, **kwargs):
                if cmd[0] == "journalctl":
                    return "i915 GPU HANG: ecode 12\ni915 *ERROR* Atomic update failure\ni915 GPU reset"
                return ""

            mock_run.side_effect = mock_run_side_effect
            mock_sub_run.return_value = MagicMock(stdout="", returncode=0, stderr="")

            summary = plasma_capture.capture_frozen_plasma()
            self.assertTrue(summary["gpu_hang_in_recent_window"])
            self.assertTrue(summary["i915_atomic_event_in_recent_window"])
            self.assertTrue(summary["gpu_reset_in_recent_window"])

    def test_no_dangerous_commands_in_source(self):
        source = Path(plasma_capture.__file__).read_text()

        # Mutating commands
        dangerous = ["kill", "killall", "pkill", "reboot", "shutdown", "systemctl restart", "systemctl stop", "systemctl kill", "loginctl terminate", "grub", "modprobe", "rmmod", "tee /sys/"]
        for d in dangerous:
            self.assertNotIn(d, source.lower())

    @patch('plasma_capture.datetime')
    @patch('plasma_capture.subprocess.run')
    @patch('plasma_capture.Path.home')
    def test_forced_directory_collision_suffix(self, mock_home, mock_sub_run, mock_datetime):
        from datetime import datetime, timezone
        with tempfile.TemporaryDirectory() as tmp:
            mock_home.return_value = Path(tmp)
            mock_sub_run.return_value = MagicMock(stdout="", returncode=0, stderr="")

            # Freeze time
            fixed_time = datetime(2026, 8, 28, 13, 0, 0, tzinfo=timezone.utc)
            mock_datetime.now.return_value = fixed_time

            # Capture 1
            res1 = plasma_capture.capture_frozen_plasma()
            path1 = Path(res1["capture_path"])
            self.assertTrue(path1.exists())
            self.assertTrue(path1.name.endswith("20260828-130000-000000"))

            # Capture 2 with EXACTLY the same mock datetime
            res2 = plasma_capture.capture_frozen_plasma()
            path2 = Path(res2["capture_path"])
            self.assertTrue(path2.exists())

            # Assert paths differ
            self.assertNotEqual(path1, path2)

            # First capture is not overwritten (we can check both exist independently)
            self.assertTrue(path1.exists())
            self.assertTrue(path2.exists())

            # Second capture gets -001 suffix
            self.assertTrue(path2.name.endswith("20260828-130000-000000-001"))

            # Let's do a third one
            res3 = plasma_capture.capture_frozen_plasma()
            path3 = Path(res3["capture_path"])
            self.assertTrue(path3.name.endswith("20260828-130000-000000-002"))

    @patch('fedora_crash_doctor.QMessageBox')
    def test_gui_integration_worker(self, mock_msg):
        # We need to test the GUI worker thread integration without starting real Qt event loop if possible
        # We can just manually call the slots.
        from PySide6.QtCore import QObject
        from fedora_crash_doctor import MainWindow
        import sys

        # We simulate the worker thread lifecycle
        window = MainWindow()
        window.freeze_capture_btn.setEnabled(True)

        # Test 1. MainWindow opens
        self.assertIsNotNone(window.freeze_capture_btn)

        # Mock the run_plasma_capture to just emit the signal directly for testing
        # because QThread testing in unittest without an event loop can be tricky
        summary = {"capture_complete": True, "failed_collectors": [], "capture_path": "/tmp/fake"}

        # Trigger button
        window.freeze_capture_btn.setEnabled(False)
        self.assertFalse(window.freeze_capture_btn.isEnabled())

        # Worker completion signal arrives
        window.on_plasma_capture_finished(summary)

        # Button enabled again
        self.assertTrue(window.freeze_capture_btn.isEnabled())

    @patch('plasma_capture.capture_frozen_plasma')
    def test_cli_fallback(self, mock_capture):
        mock_capture.return_value = {"capture_path": "/test/path", "failed_collectors": ["a"]}

        import io
        import sys
        captured_out = io.StringIO()
        old_out = sys.stdout
        try:
            sys.stdout = captured_out
            plasma_capture.main()
        finally:
            sys.stdout = old_out

        out = captured_out.getvalue()
        self.assertIn("Capture path: /test/path", out)
        self.assertIn("Partial failures: a", out)

if __name__ == "__main__":
    unittest.main()
