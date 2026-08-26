#!/usr/bin/env python3
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from freeze_classifiers import classify_freeze_evidence


class FreezeClassifierTests(unittest.TestCase):
    def test_display_stack_hang(self):
        classes = classify_freeze_evidence([
            {"id": "intel_display", "evidence": ["i915: [drm] *ERROR* Atomic update failure on pipe B"]},
            {"id": "wayland", "evidence": ["kwin_wayland became unresponsive"]},
        ])
        self.assertEqual(classes[0]["id"], "display_stack_compositor_hang")
        self.assertEqual(classes[0]["confidence"], "high")

    def test_memory_pressure_desktop_starvation(self):
        samples = [{
            "memory": {"mem_available_mb": 475, "swap_used_mb": 8191, "swap_total_mb": 8192},
            "psi_io": {"full_avg10": 85.0},
            "psi_mem": {"some_avg10": 35.0},
            "load1": 33.0,
        }]
        classes = classify_freeze_evidence([], {"samples": samples})
        memory = [item for item in classes if item["id"] == "memory_pressure_desktop_starvation"][0]
        self.assertEqual(memory["confidence"], "high")

    def test_pcie_aer_is_low_confidence_without_correlation(self):
        classes = classify_freeze_evidence([
            {"id": "pcie", "evidence": ["rtw88_8821ce 0000:02:00.0: PCIe Bus Error: severity=Correctable"]}
        ])
        pcie = [item for item in classes if item["id"] == "correctable_pcie_aer_observed"][0]
        self.assertEqual(pcie["confidence"], "low")


if __name__ == "__main__":
    unittest.main()
