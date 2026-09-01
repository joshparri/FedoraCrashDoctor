import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import chrome_capture


CAPTURE_TIME = datetime(2026, 8, 28, 10, 0, tzinfo=timezone.utc)


def summary():
    return {"capture_time": CAPTURE_TIME.isoformat(), "boot_id": "boot-current"}


class ChromeCaptureTests(unittest.TestCase):
    def classify(self, lines):
        return chrome_capture.classify_chrome_incident(summary(), {"chrome": lines})

    def test_historical_oom_is_not_current(self):
        result = self.classify("2026-08-27T10:00:00+00:00 host systemd-oomd: Killed chrome")
        self.assertNotIn("confirmed_oom_kill", [item["type"] for item in result])

    def test_current_oomd_kill_is_confirmed(self):
        result = self.classify("2026-08-28T09:59:00+00:00 host systemd-oomd: Killed /app-chrome.scope")
        self.assertIn("confirmed_oom_kill", [item["type"] for item in result])

    def test_compositor_warning_is_observation_only(self):
        result = self.classify("2026-08-28T09:59:00+00:00 host chrome: CompositorAnimationObserver is active for too long")
        self.assertIn("chrome_compositor_stall_observed", [item["type"] for item in result])
        self.assertNotIn("gpu", next(item for item in result if item["type"] == "chrome_compositor_stall_observed")["observation"].lower())

    def test_i915_near_compositor_is_correlation(self):
        lines = "\n".join([
            "2026-08-28T09:58:30+00:00 host kernel: i915 [drm] atomic update failure",
            "2026-08-28T09:59:00+00:00 host chrome: CompositorAnimationObserver is active for too long",
        ])
        result = self.classify(lines)
        item = next(item for item in result if item["type"] == "display_stack_correlation")
        self.assertIn("correlation, not causation", item["observation"])
        self.assertIn("30 seconds before", item["observation"])

    def test_chrome_coredump_is_distinct_process_crash(self):
        import json
        mock_json = json.dumps({"COREDUMP_PID": "1234", "COREDUMP_EXE": "/opt/google/chrome/chrome", "__REALTIME_TIMESTAMP": "1788303225056929", "COREDUMP_SIGNAL_NAME": "SIGSEGV"})
        result = chrome_capture.classify_chrome_incident(summary(), {"coredumps": mock_json, "chrome": ""})
        self.assertEqual(result[0]["type"], "confirmed_process_crash")

    def test_process_vanished_without_evidence_is_unknown(self):
        result = self.classify("")
        self.assertEqual(result[0]["type"], "no_system_level_failure_found")
        self.assertIn("not thereby proven healthy", result[0]["observation"])

    @patch("chrome_capture._meminfo", return_value={"MemTotal": 100, "MemAvailable": 50, "SwapTotal": 1000, "SwapFree": 400})
    @patch("chrome_capture._read")
    def test_actual_swap_bytes_are_parsed(self, read, _meminfo):
        read.side_effect = lambda path: "Filename Type Size Used Priority\n/swapfile file 1000 600 10\n" if str(path) == "/proc/swaps" else ""
        self.assertEqual(chrome_capture.collect_memory()["SwapUsed_bytes"], 600)

    @patch("chrome_capture._meminfo", return_value={"SwapTotal": 1000, "SwapFree": 400})
    @patch("chrome_capture._read")
    def test_zram_and_disk_swap_are_separate(self, read, _meminfo):
        read.side_effect = lambda path: "Filename Type Size Used Priority\n/dev/zram0 partition 800 200 100\n/swapfile file 1000 400 10\n" if str(path) == "/proc/swaps" else ""
        memory = chrome_capture.collect_memory()
        self.assertEqual(memory["zram_devices"][0]["used_bytes"], 200 * 1024)
        self.assertEqual(memory["disk_swap_devices"][0]["used_bytes"], 400 * 1024)
        self.assertNotIn("Yes", json.dumps(memory))

    @patch("chrome_capture.collect_crashpad", return_value=("", []))
    @patch("chrome_capture.collect_chrome_cgroups", return_value={"cgroups": []})
    @patch("chrome_capture.collect_memory", return_value={"SwapUsed_bytes": 0, "zram_devices": [], "disk_swap_devices": []})
    @patch("chrome_capture.collect_chrome_processes")
    def capture(self, processes, memory, cgroups, crashpad):
        processes.return_value = self.processes()
        def runner(command, _timeout):
            if command[0] == "journalctl":
                return ""
            if command[0] == "coredumpctl":
                return ""
            return "value"
        with tempfile.TemporaryDirectory() as temp:
            result = chrome_capture.capture_chrome_incident(runner=runner, home=Path(temp), now=CAPTURE_TIME)
            return result, Path(result["capture_path"])

    @staticmethod
    def processes():
        return [
            {"pid": 10, "ppid": 1, "process_type": "browser", "rss_bytes": 100, "vsz_bytes": 200, "stat": "S", "wchan": "poll", "cpu_percent": None, "elapsed": None, "command_line": "/opt/google-chrome --ozone-platform=wayland --disable-gpu-compositing"},
            {"pid": 11, "ppid": 10, "process_type": "renderer", "rss_bytes": 300, "vsz_bytes": 500, "stat": "S", "wchan": "futex", "cpu_percent": None, "elapsed": None, "command_line": "/opt/google-chrome --type=renderer"},
        ]

    def test_chrome_process_count_is_recorded(self):
        result, _path = self.capture()
        self.assertEqual(result["chrome_process_count"], 2)

    def test_total_rss_is_explicitly_aggregate(self):
        result, _path = self.capture()
        self.assertEqual(result["chrome_aggregate_rss_bytes"], 400)
        self.assertIn("double-count", result["chrome_aggregate_rss_note"])

    def test_command_line_flags_are_preserved_objectively(self):
        result, _path = self.capture()
        self.assertTrue(any("--disable-gpu-compositing" in item for item in result["chrome_gpu_mode_evidence"]))

    def test_disable_gpu_flag_does_not_create_diagnosis(self):
        result, _path = self.capture()
        self.assertEqual(result["classifications"][0]["type"], "no_system_level_failure_found")

    def test_empty_graphics_journal_is_valid(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch("chrome_capture.collect_chrome_processes", return_value=[]), patch("chrome_capture.collect_memory", return_value={}), patch("chrome_capture.collect_chrome_cgroups", return_value={"cgroups": []}), patch("chrome_capture.collect_crashpad", return_value=("", [])):
                result = chrome_capture.capture_chrome_incident(runner=lambda _command, _timeout: "", home=Path(temp), now=CAPTURE_TIME)
            path = Path(result["capture_path"])
            self.assertTrue((path / "graphics-journal.txt").exists())
            self.assertEqual((path / "graphics-journal.txt").read_text(), "")

    def test_empty_chrome_journal_is_valid(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch("chrome_capture.collect_chrome_processes", return_value=[]), patch("chrome_capture.collect_memory", return_value={}), patch("chrome_capture.collect_chrome_cgroups", return_value={"cgroups": []}), patch("chrome_capture.collect_crashpad", return_value=("", [])):
                result = chrome_capture.capture_chrome_incident(runner=lambda _command, _timeout: "", home=Path(temp), now=CAPTURE_TIME)
            path = Path(result["capture_path"])
            self.assertTrue((path / "chrome-journal.txt").exists())
            self.assertEqual((path / "chrome-journal.txt").read_text(), "")

    def test_failed_collector_does_not_abort_capture(self):
        def runner(command, _timeout):
            if command[0] == "journalctl":
                return "[ERROR] collector timeout"
            return "value"
        with tempfile.TemporaryDirectory() as temp, patch("chrome_capture.collect_chrome_processes", return_value=[]), patch("chrome_capture.collect_memory", return_value={}), patch("chrome_capture.collect_chrome_cgroups", return_value={"cgroups": []}), patch("chrome_capture.collect_crashpad", return_value=("", [])):
            result = chrome_capture.capture_chrome_incident(runner=runner, home=Path(temp), now=CAPTURE_TIME)
        self.assertTrue(result["capture_complete"])

    def test_capture_uses_collision_safe_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch("chrome_capture.collect_chrome_processes", return_value=[]), patch("chrome_capture.collect_memory", return_value={}), patch("chrome_capture.collect_chrome_cgroups", return_value={"cgroups": []}), patch("chrome_capture.collect_crashpad", return_value=("", [])):
                runner = lambda _command, _timeout: ""
                first = chrome_capture.capture_chrome_incident(runner=runner, home=Path(temp), now=CAPTURE_TIME)
                second = chrome_capture.capture_chrome_incident(runner=runner, home=Path(temp), now=CAPTURE_TIME)
        self.assertNotEqual(first["capture_path"], second["capture_path"])
        self.assertTrue(first["capture_path"].endswith("20260828-100000-000000"))
        self.assertTrue(second["capture_path"].endswith("20260828-100000-000000-001"))

    def test_no_destructive_commands_are_invoked(self):
        commands = []
        def runner(command, _timeout):
            commands.append(command)
            return ""
        with tempfile.TemporaryDirectory() as temp, patch("chrome_capture.collect_chrome_processes", return_value=[]), patch("chrome_capture.collect_memory", return_value={}), patch("chrome_capture.collect_chrome_cgroups", return_value={"cgroups": []}), patch("chrome_capture.collect_crashpad", return_value=("", [])):
            chrome_capture.capture_chrome_incident(runner=runner, home=Path(temp), now=CAPTURE_TIME)
        self.assertFalse(any(command and command[0] in {"pkill", "kill", "killall", "reboot", "shutdown"} for command in commands))

    def test_boot_aware_window_requires_precise_current_window(self):
        result = self.classify("2026-08-28T09:49:59+00:00 host systemd-oomd: Killed chrome")
        self.assertNotIn("confirmed_oom_kill", [item["type"] for item in result])

    def test_cli_entry_point_exists(self):
        self.assertTrue(callable(chrome_capture.main))

    def test_capture_writes_summary_json(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch("chrome_capture.collect_chrome_processes", return_value=[]), patch("chrome_capture.collect_memory", return_value={}), patch("chrome_capture.collect_chrome_cgroups", return_value={"cgroups": []}), patch("chrome_capture.collect_crashpad", return_value=("", [])):
                result = chrome_capture.capture_chrome_incident(runner=lambda _command, _timeout: "", home=Path(temp), now=CAPTURE_TIME)
            loaded = json.loads((Path(result["capture_path"]) / "summary.json").read_text())
            self.assertEqual(loaded["capture_path"], result["capture_path"])

    @patch("fedora_crash_doctor.ChromeCaptureWorker")
    def test_gui_worker_class_is_available(self, worker):
        from fedora_crash_doctor import ChromeCaptureWorker
        self.assertIsNotNone(ChromeCaptureWorker)


if __name__ == "__main__":
    unittest.main()