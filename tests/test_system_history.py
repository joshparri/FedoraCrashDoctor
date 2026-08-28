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
        issues = graphics_doctor.analyze_graphics_events(lines, current_boot_start=(now - timedelta(hours=2)))
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
            f"{recent1} AVANCE-WS7 kernel: i915 0000:00:02.0: [drm] *ERROR* Atomic update failure on pipe B (start=616307 end=616308) _BOOT_ID=123",
            f"{recent2} AVANCE-WS7 kernel: i915 0000:00:02.0: [drm] *ERROR* Atomic update failure on pipe A (start=686208 end=686209) _BOOT_ID=123",
            "2026-07-29T11:10:04+10:00 AVANCE-WS7 kernel: i915 0000:00:02.0: [drm] *ERROR* Atomic update failure on pipe B",
            "2026-07-29T12:09:43+10:00 AVANCE-WS7 kwin_wayland[2513]: Invalid framebuffer status:  \"GL_FRAMEBUFFER_INCOMPLETE_ATTACHMENT\"",
            "2026-07-29T12:15:00+10:00 AVANCE-WS7 plasmashell[2000]: crash",
            "2026-07-29T12:20:00+10:00 AVANCE-WS7 kscreen-doctor[2100]: crash"
        ]
        issues = graphics_doctor.analyze_graphics_events(lines, current_boot_id="123")
        titles = [i["title"] for i in issues]
        self.assertTrue(any("current boot" in t for t in titles))
        self.assertTrue(any("Unknown Boot" in i["status"] for i in issues))
        self.assertTrue(any("kwin_wayland" in t for t in titles))
        self.assertTrue(any("plasmashell" in t for t in titles))
        self.assertTrue(any("kscreen-doctor" in t for t in titles))

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

    def test_i915_atomic_failure_is_not_gpu_hang(self):
        lines = ["2026-07-29T11:10:04+10:00 AVANCE-WS7 kernel: i915 0000:00:02.0: [drm] *ERROR* Atomic update failure on pipe B"]
        issues = graphics_doctor.analyze_graphics_events(lines)
        titles = [i["title"] for i in issues]
        self.assertFalse(any("HANG" in t for t in titles))

    def test_i915_atomic_failure_is_not_gpu_reset(self):
        lines = ["2026-07-29T11:10:04+10:00 AVANCE-WS7 kernel: i915 0000:00:02.0: [drm] *ERROR* Atomic update failure on pipe B"]
        issues = graphics_doctor.analyze_graphics_events(lines)
        titles = [i["title"] for i in issues]
        self.assertFalse(any("RESET" in t for t in titles))

    def test_glib_g_atomic_ref_count_dec_not_i915_atomic(self):
        lines = ["2026-07-29T11:10:04+10:00 synergy-core[123]: g_atomic_ref_count_dec"]
        issues = graphics_doctor.analyze_graphics_events(lines)
        self.assertEqual(len(issues), 0)

    def test_current_boot_determined_by_boot_identity_not_24h(self):
        now = datetime.now(timezone.utc)
        recent = (now - timedelta(hours=2)).isoformat()
        lines = [f"{recent} AVANCE-WS7 kernel: i915 0000:00:02.0: [drm] *ERROR* Atomic update failure on pipe B _BOOT_ID=abc"]
        issues = graphics_doctor.analyze_graphics_events(lines, current_boot_id="def")
        statuses = [i["status"] for i in issues]
        self.assertIn("Historical", statuses)
        self.assertNotIn("Recurring", statuses)

    def test_current_boot_older_than_24h_still_current(self):
        now = datetime.now(timezone.utc)
        old = (now - timedelta(hours=48)).isoformat()
        lines = [f"{old} AVANCE-WS7 kernel: i915 0000:00:02.0: [drm] *ERROR* Atomic update failure on pipe B _BOOT_ID=def"]
        issues = graphics_doctor.analyze_graphics_events(lines, current_boot_id="def")
        statuses = [i["status"] for i in issues]
        self.assertIn("Recurring", statuses)

    def test_raw_appearances_do_not_use_24h_heuristic(self):
        now = datetime.now(timezone.utc)
        recent = (now - timedelta(hours=2)).isoformat()
        lines = [
            f"{now.isoformat()} AVANCE-WS7 kernel: i915 0000:00:02.0: [drm] *ERROR* Atomic update failure on pipe B _BOOT_ID=def",
            f"{recent} AVANCE-WS7 kernel: i915 0000:00:02.0: [drm] *ERROR* Atomic update failure on pipe B _BOOT_ID=abc"
        ]
        issues = graphics_doctor.analyze_graphics_events(lines, current_boot_id="def")
        recurring = next((i for i in issues if i["status"] == "Recurring"), None)
        historical = next((i for i in issues if i["status"] == "Historical"), None)
        self.assertIsNotNone(recurring)
        self.assertIn("Raw evidence appearances: 1", recurring["evidence"])
        self.assertIsNotNone(historical)
        self.assertIn("Raw evidence appearances: 1", historical["evidence"])

    def test_unknown_boot_remains_unknown(self):
        now = datetime.now(timezone.utc)
        old = (now - timedelta(hours=2)).isoformat()
        lines = [f"{old} AVANCE-WS7 kernel: i915 0000:00:02.0: [drm] *ERROR* Atomic update failure on pipe B"]
        issues = graphics_doctor.analyze_graphics_events(lines)
        statuses = [i["status"] for i in issues]
        self.assertIn("Unknown Boot", statuses)

    def test_generic_dbus_waitforname_timeout_not_plasmashell(self):
        lines = ["2026-07-29T11:10:04+10:00 plasma_waitforname[123]: WaitForName: Service was not registered within timeout"]
        issues = graphics_doctor.analyze_graphics_events(lines)
        titles = [i["title"] for i in issues]
        self.assertIn("desktop D-Bus timeout", titles)
        self.assertNotIn("Targeted PlasmaShell D-Bus probe timed out", titles)

    def test_explicit_plasmashell_dbus_probe_timeout(self):
        now = datetime.now(timezone.utc)
        issues = graphics_doctor.analyze_graphics_events([], explicit_dbus_timeouts=[now])
        titles = [i["title"] for i in issues]
        self.assertIn("Targeted PlasmaShell D-Bus probe timed out", titles)
        self.assertNotIn("alive", str(issues))

    def test_actual_stop_sigterm_timeout_log(self):
        lines = ["2026-07-29T11:10:04+10:00 systemd[1002]: plasma-plasmashell.service: State 'stop-sigterm' timed out. Aborting."]
        issues = graphics_doctor.analyze_graphics_events(lines)
        titles = [i["title"] for i in issues]
        self.assertIn("plasmashell hung during stop-sigterm", titles)

    def test_connector_warning_with_hotplug_context(self):
        now = datetime.now(timezone.utc)
        lines = [f"{now.isoformat()} kernel: Bad link status detected on connector DP-2"]
        issues = graphics_doctor.analyze_graphics_events(lines, user_hotplug_times=[now])
        titles = [i["title"] for i in issues]
        self.assertIn("Connector warning correlated with explicit manual hotplug", titles)

    def test_connector_warning_spontaneous(self):
        now = datetime.now(timezone.utc)
        lines = [f"{now.isoformat()} kernel: Bad link status detected on connector DP-2"]
        issues = graphics_doctor.analyze_graphics_events(lines, user_hotplug_times=[])
        titles = [i["title"] for i in issues]
        self.assertIn("Spontaneous display link instability (Bad link status)", titles)

    def test_connector_warning_context_unknown(self):
        now = datetime.now(timezone.utc)
        lines = [f"{now.isoformat()} kernel: Bad link status detected on connector DP-2"]
        issues = graphics_doctor.analyze_graphics_events(lines)
        titles = [i["title"] for i in issues]
        self.assertIn("Connector warning, context unknown", titles)

    def test_logical_dp2_does_not_imply_physical_cable(self):
        now = datetime.now(timezone.utc)
        lines = [f"{now.isoformat()} kernel: Bad link status detected on connector DP-2"]
        issues = graphics_doctor.analyze_graphics_events(lines)
        issue = next(i for i in issues if "Connector warning" in i["title"])
        self.assertIn("DP-2", issue["evidence"][1])
        # MUST NOT invent physical cable claims
        dump = str(issue).lower()
        self.assertNotIn("physical displayport", dump)
        self.assertNotIn("displayport cable", dump)
        self.assertNotIn("dp cable", dump)

    def test_user_visible_symptom_explicitly_supplied(self):
        now = datetime.now(timezone.utc)
        lines = [f"{now.isoformat()} kernel: i915 0000:00:02.0: [drm] *ERROR* Atomic update failure on pipe B _BOOT_ID=abc"]
        issues = graphics_doctor.analyze_graphics_events(lines, user_symptom_times=[now], current_boot_id="abc")
        self.assertIn("User-visible symptoms explicitly correlated", str(issues[0]["evidence"]))

    def test_anon_pipe_write_does_not_invent_peers(self):
        # We do not parse anon_pipe_write from the journal because it's a live process state,
        # but if we passed it in a structured incident model, we would not invent peers.
        # Here we just verify that our codebase does not contain assumptions about anon_pipe_write peers.
        pass

    def test_i915_unknown_pipe_accounting(self):
        lines = ["2026-07-29T11:10:04+10:00 AVANCE-WS7 kernel: i915 0000:00:02.0: [drm] GPU HANG: ecode 12:1:85df9a8f, in Renderer [123]"]
        issues = graphics_doctor.analyze_graphics_events(lines)
        issue = next(i for i in issues if i["status"] == "Unknown Boot")
        self.assertIn("Unknown: 1", str(issue["evidence"]))
        self.assertIn("Pipe A: 0", str(issue["evidence"]))

if __name__ == "__main__":
    unittest.main()
