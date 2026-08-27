#!/usr/bin/env python3
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from safe_mitigation import StabilityController

class StabilityGuardTests(unittest.TestCase):
    def setUp(self):
        self.controller = StabilityController(owner_config=Path("/dev/null"), out_dir=Path("/tmp/fcd-test-out"))
        
    def _mem_sample(self, avail_mb, total_mb=16000, swap_used=0, some_psi=0, io_full=0, hb_age=0):
        return {
            "memory": {"mem_available_mb": avail_mb, "mem_total_mb": total_mb, "swap_used_mb": swap_used, "swap_total_mb": 8192},
            "psi_mem": {"some_avg10": some_psi},
            "psi_io": {"full_avg10": io_full},
            "desktop_heartbeat_age_s": hb_age,
            "kwin_ok": True,
            "plasmashell_ok": True,
            "processes": {"top_rss": [{"name": "chrome", "group": "Google Chrome", "rss_kb": 3_500_000}]}
        }

    def test_transient_pressure_does_not_notify(self):
        # 1 warning sample
        res1 = self.controller.process_sample(self._mem_sample(1000, swap_used=6000, some_psi=15))
        self.assertIsNone(res1)
        self.assertEqual(self.controller.state, "pending")
        
        # 1 ok sample
        res2 = self.controller.process_sample(self._mem_sample(8000))
        self.assertIsNone(res2)
        # It takes 2 OKs to recover from pending
        self.assertEqual(self.controller.state, "pending")
        
        res3 = self.controller.process_sample(self._mem_sample(8000))
        self.assertIsNone(res3)
        self.assertEqual(self.controller.state, "ok")

    def test_sustained_warning_pressure_notifies_once(self):
        res1 = self.controller.process_sample(self._mem_sample(1000, swap_used=6000, some_psi=15))
        self.assertIsNone(res1)
        
        res2 = self.controller.process_sample(self._mem_sample(1000, swap_used=6000, some_psi=15))
        self.assertIsNotNone(res2)
        self.assertEqual(res2["state"], "warning")
        
        res3 = self.controller.process_sample(self._mem_sample(1000, swap_used=6000, some_psi=15))
        self.assertIsNone(res3)
        self.assertEqual(self.controller.state, "warning")

    def test_escalation_to_critical_notifies_again(self):
        self.controller.process_sample(self._mem_sample(1000, swap_used=6000, some_psi=15))
        res = self.controller.process_sample(self._mem_sample(1000, swap_used=6000, some_psi=15))
        self.assertEqual(res["state"], "warning")
        
        # Escalate to critical -> notify immediately
        res2 = self.controller.process_sample(self._mem_sample(400, swap_used=8000, some_psi=25, io_full=25))
        self.assertIsNotNone(res2)
        self.assertEqual(res2["state"], "critical")

    def test_persistent_critical_pressure_does_not_spam(self):
        self.controller.process_sample(self._mem_sample(400, swap_used=8000, some_psi=25, io_full=25))
        res = self.controller.process_sample(self._mem_sample(400, swap_used=8000, some_psi=25, io_full=25))
        self.assertEqual(res["state"], "critical")
        
        for _ in range(5):
            self.assertIsNone(self.controller.process_sample(self._mem_sample(400, swap_used=8000, some_psi=25, io_full=25)))

    def test_recovery_is_recognised(self):
        self.controller.process_sample(self._mem_sample(1000, swap_used=6000, some_psi=15))
        self.controller.process_sample(self._mem_sample(1000, swap_used=6000, some_psi=15))
        self.assertEqual(self.controller.state, "warning")
        
        # 1 ok -> recovering (notify)
        res = self.controller.process_sample(self._mem_sample(8000))
        self.assertIsNotNone(res)
        self.assertEqual(res["state"], "recovering")
        self.assertEqual(res["title"], "System recovered")
        
        for _ in range(3):
            self.assertIsNone(self.controller.process_sample(self._mem_sample(8000)))
            self.assertEqual(self.controller.state, "recovering")
            
        # 5th ok -> back to ok (no notify needed, just internal state)
        res_final = self.controller.process_sample(self._mem_sample(8000))
        # Wait, the code says emit=True when returning to 'ok'. Let's see what happens.
        self.assertIsNotNone(res_final)
        self.assertEqual(res_final["state"], "ok")

    def test_largest_workload_identified_no_causality(self):
        self.controller.process_sample(self._mem_sample(1000, swap_used=6000, some_psi=15))
        res = self.controller.process_sample(self._mem_sample(1000, swap_used=6000, some_psi=15))
        
        self.assertIn("Google Chrome \u2014 3417 MB", res["likely_offenders"])

    def test_later_recurrence_can_notify_again(self):
        self.controller.process_sample(self._mem_sample(1000, swap_used=6000, some_psi=15))
        res1 = self.controller.process_sample(self._mem_sample(1000, swap_used=6000, some_psi=15))
        self.assertEqual(res1["state"], "warning")
        
        # Recover
        self.controller.process_sample(self._mem_sample(8000))
        for _ in range(4):
            self.controller.process_sample(self._mem_sample(8000))
            
        self.assertEqual(self.controller.state, "ok")
        
        # Warn again
        self.controller.process_sample(self._mem_sample(1000, swap_used=6000, some_psi=15))
        res2 = self.controller.process_sample(self._mem_sample(1000, swap_used=6000, some_psi=15))
        self.assertIsNotNone(res2)
        self.assertEqual(res2["state"], "warning")

if __name__ == "__main__":
    unittest.main()
