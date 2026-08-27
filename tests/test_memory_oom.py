import unittest
from datetime import datetime, timezone, timedelta
from memory_oom import parse_systemd_oomd_events, analyze_oom_events

class TestMemoryOOM(unittest.TestCase):
    def test_parse_events(self):
        journal_output = """2026-08-27T15:51:41+1000 AVANCE-WS7 systemd-oomd[709]: Considered 41 cgroups for killing, top candidates were:
2026-08-27T15:51:41+1000 AVANCE-WS7 systemd-oomd[709]:         Path: /user.slice/user-1002.slice/user@1002.service/app.slice/app-chrome\\x2diidheibmjbpieikekgapdklcblnmllmh\\x2dDefault@8fdcfdb58bff44a786afdfbe01c7edf7.service
2026-08-27T15:51:41+1000 AVANCE-WS7 systemd-oomd[709]:                 Swap Usage: 2.5G
2026-08-27T15:51:41+1000 AVANCE-WS7 systemd-oomd[709]: Killed /user.slice/user-1002.slice/user@1002.service/app.slice/app-chrome\\x2diidheibmjbpieikekgapdklcblnmllmh\\x2dDefault@8fdcfdb58bff44a786afdfbe01c7edf7.service due to memory used (22369452032) / total (24681861120) and swap used (8589910016) / total (8589930496) being more than 90.00%
2026-08-27T16:10:19+1000 AVANCE-WS7 systemd-oomd[709]: Considered 43 cgroups for killing, top candidates were:
2026-08-27T16:10:19+1000 AVANCE-WS7 systemd-oomd[709]:         Path: /user.slice/user-1002.slice/user@1002.service/app.slice/app-org.chromium.Chromium-3905462.scope
2026-08-27T16:10:19+1000 AVANCE-WS7 systemd-oomd[709]:                 Swap Usage: 2.8G
2026-08-27T16:10:19+1000 AVANCE-WS7 systemd-oomd[709]: Killed /user.slice/user-1002.slice/user@1002.service/app.slice/app-org.chromium.Chromium-3905462.scope due to memory used (22240563200) / total (24681861120) and swap used (8589836288) / total (8589930496) being more than 90.00%
"""
        events = parse_systemd_oomd_events(journal_output)
        self.assertEqual(len(events), 2)
        
        self.assertEqual(events[0]["app_name"], "Chrome")
        self.assertEqual(events[0]["system_swap_percent"], 100 * 8589910016 / 8589930496)
        self.assertEqual(events[0]["victim_swap_usage"], "2.5G")
        
        self.assertEqual(events[1]["app_name"], "Chromium")
        self.assertEqual(events[1]["system_swap_percent"], 100 * 8589836288 / 8589930496)
        self.assertEqual(events[1]["victim_swap_usage"], "2.8G")
        
        # Test analysis with simulated current time right after the events
        now = datetime.fromisoformat("2026-08-27T16:20:00+1000").astimezone(timezone.utc)
        issues = analyze_oom_events(events, zram_only=True, has_disk_swap=False)
        
        self.assertTrue(any("CONFIRMED: Repeated systemd-oomd kills caused by swap exhaustion" in i["title"] for i in issues))
        
    def test_year_boundary(self):
        line = "Dec 31 23:59:59 AVANCE-WS7 systemd-oomd[709]: Killed /app.slice due to memory used (1) / total (2) and swap used (3) / total (4) being more than 90.00%"
        events = parse_systemd_oomd_events(line)
        self.assertEqual(len(events), 1)
        
        issues = analyze_oom_events(events, zram_only=False, has_disk_swap=False)
        self.assertEqual(len(issues), 0)

if __name__ == "__main__":
    unittest.main()
