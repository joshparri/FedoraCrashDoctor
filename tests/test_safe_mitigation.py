#!/usr/bin/env python3
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from safe_mitigation import evaluate_sample


class SafeMitigationTests(unittest.TestCase):
    def test_memory_pressure_warning_does_not_take_action(self):
        result = evaluate_sample({
            "memory": {"mem_available_mb": 400, "mem_total_mb": 24000, "swap_used_mb": 7800, "swap_total_mb": 8192},
            "psi_mem": {"some_avg10": 35},
            "psi_io": {"full_avg10": 63},
            "load1": 28,
            "processes": {"top_rss": [{"pid": 1, "name": "chrome", "group": "Google Chrome", "rss_kb": 4_000_000, "swap_kb": 200_000}]},
        })
        self.assertEqual(result["severity"], "critical")
        self.assertFalse(result["automatic_action_taken"])
        self.assertTrue(any("Google Chrome" in x for x in result["likely_offenders"]))

    def test_plasma_shell_only_recovery_suggestion(self):
        result = evaluate_sample({"plasmashell_ok": False, "kwin_ok": True})
        self.assertEqual(result["plasma_shell_recovery"], "Offer plasmashell --replace as a panel-only recovery action.")


if __name__ == "__main__":
    unittest.main()
