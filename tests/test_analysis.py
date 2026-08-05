#!/usr/bin/env python3
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from collector import analyse, analyse_canary, build_incidents, build_timeline, extract_pcie_devices, parse_lspci_inventory


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
            "previous_errors": check("prev", "2026-07-29T12:26:00+1000 host kernel: i915 0000:00:02.0: [drm] *ERROR* Atomic update failure on pipe A"),
            "boot_history": check("boot", "reboot   system boot  7.1.5-200.fc44.x Wed Jul 29 12:26 - crash  (03:25)"),
            "journal_boots": check("boots", "-1 e2110b7c6f7e4e72afca6dfe736dbfb8 Wed 2026-07-29 12:26:00 AEST Wed 2026-07-29 12:26:00 AEST")
        }
        findings, _ = analyse(checks)
        incidents, _ = build_incidents(findings, checks)
        self.assertEqual(len(incidents), 1)
        self.assertTrue("Display-stack freeze" in incidents[0]["strongest_hypothesis"])

    def test_old_i915_message_unrelated_to_current_incident(self):
        checks = {
            "display_history": check("disp", "2026-07-29T12:26:00+1000 host kernel: i915 atomic update failure on pipe A"),
            "boot_history": check("boot", ""),
            "journal_boots": check("boots", "-1 e2110b7c6f7e4e72afca6dfe736dbfb8 Wed 2026-07-29 12:26:00 AEST Wed 2026-07-29 12:26:00 AEST\n0 e2110b7c6f7e4e72afca6dfe736dbfb8 Wed 2026-07-29 13:26:00 AEST Wed 2026-07-29 13:26:00 AEST")
        }
        findings, _ = analyse(checks)
        findings[0]["evidence"] = ["2026-07-29T12:26:00+1000 host kernel: i915 atomic update failure on pipe A"]
        incidents, _ = build_incidents(findings, checks)
        self.assertEqual(len(incidents), 0)

    def test_repeated_correctable_pcie_errors_without_crash(self):
        checks = {
            "hardware_errors_history": check("hw", "2026-07-29T13:26:00+1000 host kernel: pcieport 0000:00:1c.0: AER: Multiple Correctable error message received\n2026-07-29T13:26:00+1000 host kernel: pcieport 0000:00:1c.0: AER: Multiple Correctable error message received\npcieport 0000:00:1c.0: AER: Multiple Correctable error message received"),
            "pci": check("pci", "0000:00:1c.0 PCI bridge [0604]: Intel"),
            "boot_history": check("boot", ""),
            "journal_boots": check("boots", "-1 e2110b7c6f7e4e72afca6dfe736dbfb8 Wed 2026-07-29 12:26:00 AEST Wed 2026-07-29 12:26:00 AEST\n0 e2110b7c6f7e4e72afca6dfe736dbfb8 Wed 2026-07-29 13:26:00 AEST Wed 2026-07-29 13:26:00 AEST")
        }
        findings, _ = analyse(checks)
        incidents, _ = build_incidents(findings, checks)
        self.assertEqual(len(incidents), 1)
        self.assertTrue("PCIe" in incidents[0]["strongest_hypothesis"])
        self.assertTrue("Active Warning" in incidents[0]["strongest_hypothesis"])

    def test_oom_kill_precedes_frozen_session(self):
        checks = {
            "oom_previous": check("oom", "2026-07-29T12:26:00+1000 host kernel: Out of memory: Killed process"),
            "boot_history": check("boot", "reboot   system boot  7.1.5-200.fc44.x Wed Jul 29 12:26 - crash  (03:25)"),
            "journal_boots": check("boots", "-1 e2110b7c6f7e4e72afca6dfe736dbfb8 Wed 2026-07-29 12:26:00 AEST Wed 2026-07-29 12:26:00 AEST\n0 e2110b7c6f7e4e72afca6dfe736dbfb8 Wed 2026-07-29 13:26:00 AEST Wed 2026-07-29 13:26:00 AEST")
        }
        findings, _ = analyse(checks)
        incidents, _ = build_incidents(findings, checks)
        self.assertEqual(len(incidents), 1)
        self.assertTrue("Out-of-memory" in incidents[0]["strongest_hypothesis"])

    def test_multiple_unrelated_warnings_same_boot(self):
        checks = {
            "current_kernel_errors": check("curr", "2026-07-29T13:26:00+1000 host kernel: i915 atomic update failure\n2026-07-29T13:26:00+1000 host kernel: cpu clock throttled\n2026-07-29T13:26:00+1000 host kernel: Buffer I/O error on dev sda1"),
            "boot_history": check("boot", "reboot   system boot  7.1.5-200.fc44.x Wed Jul 29 12:26 - crash  (03:25)"),
            "journal_boots": check("boots", "-1 e2110b7c6f7e4e72afca6dfe736dbfb8 Wed 2026-07-29 12:26:00 AEST Wed 2026-07-29 12:26:00 AEST\n0 e2110b7c6f7e4e72afca6dfe736dbfb8 Wed 2026-07-29 13:26:00 AEST Wed 2026-07-29 13:26:00 AEST")
        }
        findings, _ = analyse(checks)
        incidents, _ = build_incidents(findings, checks)
        incidents_boot0 = [inc for inc in incidents if inc["boot_index"] == "0"]
        self.assertTrue(len(incidents_boot0[0]["unrelated_warnings"]) > 0)

    def test_crash_insufficient_evidence(self):
        checks = {
            "boot_history": check("boot", "reboot   system boot  7.1.5-200.fc44.x Wed Jul 29 12:26 - crash  (03:25)"),
            "journal_boots": check("boots", "-1 e2110b7c6f7e4e72afca6dfe736dbfb8 Wed 2026-07-29 12:26:00 AEST Wed 2026-07-29 12:26:00 AEST\n0 e2110b7c6f7e4e72afca6dfe736dbfb8 Wed 2026-07-29 13:26:00 AEST Wed 2026-07-29 13:26:00 AEST")
        }
        findings, _ = analyse(checks)
        incidents, _ = build_incidents(findings, checks)
        self.assertEqual(len(incidents), 1)
        self.assertTrue("Unknown Kernel, Firmware or Power Failure" in incidents[0]["strongest_hypothesis"])

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

    def test_repeated_system_disk_errors_are_critical(self):
        checks = {
            "previous_errors": check("prev", "I/O error on dev nvme0n1\nI/O error on dev nvme0n1\nI/O error on dev nvme0n1"),
            "block": check("block", "nvme0n1 /dev/nvme0n1 disk 256G nvme"),
            "boot_history": check("boot", ""), "pstore": check("pstore", ""), "pci": check("pci", ""),
        }
        findings, _ = analyse(checks)
        storage = [f for f in findings if f["id"] == "storage_nvme0n1"]
        self.assertEqual(len(storage), 1)
        self.assertEqual(storage[0]["severity"], "critical")
        self.assertIn("Immediate backup", storage[0]["explanation"])

    def test_single_removable_drive_error_is_info(self):
        checks = {
            "previous_errors": check("prev", "I/O error on dev sda1"),
            "block": check("block", "sda /dev/sda disk 16G usb"),
            "boot_history": check("boot", ""), "pstore": check("pstore", ""), "pci": check("pci", ""),
        }
        findings, _ = analyse(checks)
        storage = [f for f in findings if f["id"] == "storage_sda1"]
        self.assertEqual(len(storage), 1)
        self.assertEqual(storage[0]["severity"], "info")

    def test_unsafe_removal_is_info(self):
        checks = {
            "previous_errors": check("prev", "USB disconnect\nI/O error on dev sda1 write"),
            "block": check("block", "sda /dev/sda disk 16G usb"),
            "boot_history": check("boot", ""), "pstore": check("pstore", ""), "pci": check("pci", ""),
        }
        findings, _ = analyse(checks)
        storage = [f for f in findings if f["id"] == "storage_sda1"]
        self.assertEqual(len(storage), 1)
        self.assertEqual(storage[0]["severity"], "info")
        self.assertIn("unsafe removal", storage[0]["explanation"])

    def test_smart_failure_is_critical(self):
        checks = {
            "previous_errors": check("prev", "SMART overall-health self-assessment test result: FAILED! on dev sda"),
            "block": check("block", "sda /dev/sda disk 1000G sata"),
            "boot_history": check("boot", ""), "pstore": check("pstore", ""), "pci": check("pci", ""),
        }
        findings, _ = analyse(checks)
        storage = [f for f in findings if f["id"] == "storage_sda"]
        self.assertEqual(len(storage), 1)
        self.assertEqual(storage[0]["severity"], "critical")

    def test_unidentified_device_error(self):
        checks = {
            "previous_errors": check("prev", "I/O error occurred"),
            "boot_history": check("boot", ""), "pstore": check("pstore", ""), "pci": check("pci", ""),
        }
        findings, _ = analyse(checks)
        storage = [f for f in findings if f["id"] == "storage_unknown"]
        self.assertEqual(len(storage), 1)
        self.assertEqual(storage[0]["severity"], "warning")


if __name__ == "__main__":
    unittest.main()
