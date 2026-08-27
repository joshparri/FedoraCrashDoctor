import unittest
from datetime import datetime, timezone, timedelta
import graphics_doctor
import app_crash_doctor
import hardware_doctor
import dadlan_doctor

class TestSystemHistory(unittest.TestCase):
    def test_deduplication(self):
        # Same event multiple times identically
        now = datetime.now(timezone.utc)
        recent1 = now.isoformat()
        recent2 = (now - timedelta(hours=1)).isoformat()
        
        lines = [
            # identical
            f"{recent1} AVANCE-WS7 kernel: i915 0000:00:02.0: [drm] *ERROR* Atomic update failure on pipe B (start=616307 end=616308)",
            f"{recent1} AVANCE-WS7 kernel: i915 0000:00:02.0: [drm] *ERROR* Atomic update failure on pipe B (start=616307 end=616308)",
            f"{recent1} AVANCE-WS7 kernel: i915 0000:00:02.0: [drm] *ERROR* Atomic update failure on pipe B (start=616307 end=616308)",
            # same timestamp, different message
            f"{recent1} AVANCE-WS7 kernel: i915 0000:00:02.0: [drm] *ERROR* Atomic update failure on pipe A (start=999999 end=999999)",
            # same message, different boot (different time)
            f"{recent2} AVANCE-WS7 kernel: i915 0000:00:02.0: [drm] *ERROR* Atomic update failure on pipe B (start=616307 end=616308)",
        ]
        issues = graphics_doctor.analyze_graphics_events(lines)
        titles = [i["title"] for i in issues]
        
        self.assertTrue(any("Recurring Intel display pipeline errors are present" in t for t in titles))
        recurring_issue = next(i for i in issues if "Recurring Intel display pipeline errors are present" in i["title"])
        
        evidence = str(recurring_issue["evidence"])
        # Total unique events should be 3: two at recent1 (pipe A, pipe B), one at recent2 (pipe B)
        self.assertIn("Unique events: 3", evidence)
        self.assertIn("Raw evidence appearances: 5", evidence)

    def test_graphics_events(self):
        now = datetime.now(timezone.utc)
        recent1 = now.isoformat()
        recent2 = now.isoformat()
        lines = [
            f"{recent1} AVANCE-WS7 kernel: i915 0000:00:02.0: [drm] *ERROR* Atomic update failure on pipe B (start=616307 end=616308)",
            f"{recent2} AVANCE-WS7 kernel: i915 0000:00:02.0: [drm] *ERROR* Atomic update failure on pipe A (start=686208 end=686209)",
            "2026-07-29T11:10:04+10:00 AVANCE-WS7 kernel: i915 0000:00:02.0: [drm] *ERROR* Atomic update failure on pipe B",
            "2026-07-29T12:09:43+10:00 AVANCE-WS7 kwin_wayland[2513]: Invalid framebuffer status:  \"GL_FRAMEBUFFER_INCOMPLETE_ATTACHMENT\"",
            "2026-07-29T12:15:00+10:00 AVANCE-WS7 plasmashell[2000]: crash",
            "2026-07-29T12:20:00+10:00 AVANCE-WS7 kscreen-doctor[2100]: crash"
        ]
        issues = graphics_doctor.analyze_graphics_events(lines)
        self.assertEqual(len(issues), 5)
        
    def test_antigravity_crashes(self):
        lines = [
            "Thu 2026-08-27 16:11:25 AEST 3905706 1002 1002 SIGTRAP truncated /opt/antigravity/antigravity 399.1M",
            "Thu 2026-08-06 14:14:36 AEST 3985109 1002 1002 SIGTRAP missing /usr/share/antigravity/antigravity -",
            "Thu 2026-08-06 14:15:36 AEST 3985110 1002 1002 SIGSEGV missing /usr/share/antigravity/antigravity -",
            # duplicate line:
            "Thu 2026-08-06 14:15:36 AEST 3985110 1002 1002 SIGSEGV missing /usr/share/antigravity/antigravity -"
        ]
        issues = app_crash_doctor.analyze_app_crashes(lines)
        self.assertEqual(len(issues), 1)
        issue = issues[0]
        evidence = str(issue["evidence"])
        self.assertIn("Unique incidents: 3", evidence)
        self.assertIn("Raw evidence appearances: 4", evidence)
        
    def test_hardware_events(self):
        lines = [
            "2026-08-27T10:49:00+10:00 AVANCE-WS7 kernel: rtw88_8821ce 0000:02:00.0: PCIe Bus Error: severity=Correctable, type=Data Link Layer, (Receiver ID)",
            "2026-08-27T10:49:01+10:00 AVANCE-WS7 kernel: rtw88_8821ce 0000:02:00.0: PCIe Bus Error: severity=Correctable, type=Data Link Layer, (Receiver ID)",
            "2026-08-27T10:49:01+10:00 AVANCE-WS7 kernel: usb usb1-port14: unable to enumerate USB device",
            "2026-08-24T10:49:01+10:00 AVANCE-WS7 kernel: sda: Buffer I/O error on dev sda, logical block 0, async page read"
        ]
        issues = hardware_doctor.analyze_hardware_events(lines)
        titles = [i["title"] for i in issues]
        self.assertEqual(len(issues), 3)
        self.assertTrue(any("Persistent corrected PCIe errors from Realtek Wi-Fi adapter" in t for t in titles))
        
        pcie_issue = next(i for i in issues if "Realtek" in i["title"])
        self.assertIn("Incident clusters: 1", str(pcie_issue["evidence"]))

    def test_dadlan_network_errors(self):
        failed = [
            "mnt-dadlan-Laptop01.mount  loaded failed failed /mnt/dadlan/Laptop01",
            "mnt-dadlan-Laptop02.mount  loaded failed failed /mnt/dadlan/Laptop02"
        ]
        issues = dadlan_doctor.analyze_dadlan(failed)
        self.assertEqual(len(issues), 1)
        self.assertIn("Multiple optional remote mounts currently failed", issues[0]["title"])
        self.assertIn("network", issues[0]["category"])
        
if __name__ == "__main__":
    unittest.main()
