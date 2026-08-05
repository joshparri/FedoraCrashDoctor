#!/usr/bin/env python3
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from collector import analyse, analyse_canary, build_hypotheses, build_timeline, extract_pcie_devices, parse_lspci_inventory


def check(title, output, category="Software", status="ok"):
    return {"title": title, "output": output, "category": category, "status": status, "returncode": 0, "duration_seconds": 0, "command": "test"}


class AnalysisTests(unittest.TestCase):
    def test_pcie_address_anywhere_is_mapped_to_device(self):
        pci = """0000:02:00.0 Network controller [0280]: Realtek Semiconductor Co., Ltd. RTL8821CE [10ec:c821]\n\tKernel driver in use: rtw88_8821ce\n"""
        logs = """2026-07-29T09:53:40+1000 host kernel: rtw88_8821ce 0000:02:00.0: PCIe Bus Error: severity=Correctable, type=Data Link Layer, (Receiver ID)\n2026-07-29T10:00:00+1000 host kernel: 0000:02:00.0: AER: Corrected error received\n"""
        inventory = parse_lspci_inventory(pci)
        hits = extract_pcie_devices(logs, inventory)
        self.assertIn("0000:02:00.0", hits)
        self.assertEqual(hits["0000:02:00.0"]["driver"], "rtw88_8821ce")
        self.assertIn("RTL8821CE", hits["0000:02:00.0"]["description"])
        self.assertEqual(hits["0000:02:00.0"]["likely_role"], "Wi-Fi card")
        self.assertEqual(hits["0000:02:00.0"]["count"], 2)

    def test_perf_interrupt_message_is_information_not_warning(self):
        checks = {
            "interrupt_latency": check("perf", "2026-07-29 kernel: perf: interrupt took too long (4000 > 3999), lowering kernel.perf_event_max_sample_rate to 50000"),
            "boot_history": check("boot", ""),
            "pstore": check("pstore", "No pstore crash records found."),
            "pci": check("pci", ""),
        }
        findings, _ = analyse(checks)
        perf = [f for f in findings if f["id"] == "perf_sampling_adjustment"]
        self.assertEqual(len(perf), 1)
        self.assertEqual(perf[0]["severity"], "info")
        self.assertIn("not a dependable crash predictor", perf[0]["explanation"])

    def test_timeline_marks_last_ten_minutes_as_immediate(self):
        checks = {
            "previous_boot_tail": check("tail", "\n".join([
                "2026-07-29T12:00:00.000000+1000 host kernel: i915: atomic update failure",
                "2026-07-29T12:22:00.000000+1000 host chrome: context provider failed",
                "2026-07-29T12:25:00.000000+1000 host systemd: final ordinary line",
            ]))
        }
        timeline = build_timeline(checks)
        chrome = [item for item in timeline if "context provider" in item["summary"]][0]
        self.assertEqual(chrome["proximity"], "Immediately before crash")
        self.assertEqual(timeline[-1]["category"], "Crash boundary")

    def test_graphics_hypothesis_ranks_above_unsupported_oom(self):
        checks = {
            "previous_boot_tail": check("tail", "kwin GL_FRAMEBUFFER_INCOMPLETE_ATTACHMENT\nchrome context provider failed"),
            "gpu_error_state": check("gpu", "No error state collected"),
            "pstore": check("pstore", "No pstore crash records found."),
        }
        findings = [{"id": "intel_display"}, {"id": "unclean_boot"}]
        context = {
            "hard_crash": True, "has_gpu_errors": True, "has_oom": False,
            "has_thermal": False, "has_storage": False, "has_panic": False,
        }
        hypotheses = build_hypotheses(findings, context, checks, {"samples": []})
        self.assertEqual(hypotheses[0]["category"], "Graphics")
        oom = [h for h in hypotheses if h["title"] == "Out-of-memory crash"][0]
        self.assertEqual(oom["confidence"], "low")

    def test_canary_handles_null_desktop_heartbeat_age(self):
        checks = {
            "canary_log": check("canary", '{"ts":"now","desktop_heartbeat_age_s":null,"kwin_ok":null}\n')
        }
        result = analyse_canary(checks)
        self.assertIn("samples", result)
        self.assertIn("heartbeat", result["interpretation"])


    def test_wayland_crash_is_identified(self):
        checks = {
            "previous_errors": check("prev", "wayland-server: fatal error in compositor"),
            "boot_history": check("boot", ""),
            "pstore": check("pstore", "No pstore crash records found."),
            "pci": check("pci", ""),
        }
        findings, _ = analyse(checks)
        wayland = [f for f in findings if f["id"] == "wayland"]
        self.assertEqual(len(wayland), 1)
        self.assertEqual(wayland[0]["severity"], "warning")

    def test_wayland_shutdown_is_ignored(self):
        checks = {
            "previous_errors": check("prev", "wayland-server: error disconnected\nwayland-server: terminate"),
            "boot_history": check("boot", ""),
            "pstore": check("pstore", "No pstore crash records found."),
            "pci": check("pci", ""),
        }
        findings, _ = analyse(checks)
        wayland = [f for f in findings if f["id"] == "wayland"]
        self.assertEqual(len(wayland), 0)

    def test_failed_systemd_services_near_crash(self):
        checks = {
            "previous_boot_tail": check("tail", "2026-08-04T12:00:00+1000 host systemd[1]: dbus.service: Failed with result 'exit-code'.\n2026-08-04T12:05:00+1000 host kernel: crash"),
            "boot_history": check("boot", ""),
            "pstore": check("pstore", "No pstore crash records found."),
            "pci": check("pci", ""),
        }
        findings, _ = analyse(checks)
        services = [f for f in findings if f["id"] == "failed_services"]
        self.assertEqual(len(services), 1)

    def test_failed_systemd_services_far_from_crash_ignored(self):
        checks = {
            "previous_boot_tail": check("tail", "2026-08-04T10:00:00+1000 host systemd[1]: dbus.service: Failed with result 'exit-code'.\n2026-08-04T12:05:00+1000 host kernel: crash"),
            "boot_history": check("boot", ""),
            "pstore": check("pstore", "No pstore crash records found."),
            "pci": check("pci", ""),
        }
        findings, _ = analyse(checks)
        services = [f for f in findings if f["id"] == "failed_services"]
        self.assertEqual(len(services), 0)


if __name__ == "__main__":
    unittest.main()
