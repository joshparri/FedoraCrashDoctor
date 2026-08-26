#!/usr/bin/env python3
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from telemetry_timeline import build_telemetry_timeline


class TelemetryTimelineTests(unittest.TestCase):
    def test_memory_pressure_events(self):
        events = build_telemetry_timeline([{
            "ts": "2026-08-14T10:42:18+10:00",
            "memory": {"mem_available_mb": 475, "swap_used_mb": 8191, "swap_total_mb": 8192},
            "psi_io": {"full_avg10": 63},
            "psi_mem": {"some_avg10": 35},
            "load1": 28,
            "kwin_ok": False,
        }])
        types = {event["type"] for event in events}
        self.assertIn("low_memory", types)
        self.assertIn("swap_saturated", types)
        self.assertIn("high_io_psi", types)
        self.assertIn("kwin_unresponsive", types)


if __name__ == "__main__":
    unittest.main()
