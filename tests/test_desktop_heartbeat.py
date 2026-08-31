import os
import unittest
from unittest.mock import patch

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import desktop_heartbeat


class DesktopHeartbeatTests(unittest.TestCase):
    @patch("desktop_heartbeat.subprocess.run")
    def test_environment_falls_back_to_loginctl(self, run):
        with patch.dict(os.environ, {"XDG_CURRENT_DESKTOP": "", "XDG_SESSION_TYPE": "", "XDG_SESSION_ID": "4"}, clear=False):
            run.return_value.stdout = "Type=wayland\nDesktop=KDE\n"
            self.assertEqual(desktop_heartbeat.session_environment(), ("KDE", "wayland"))

    @patch("desktop_heartbeat.subprocess.run")
    def test_ping_returns_latency_and_success(self, run):
        run.return_value.returncode = 0
        with patch("desktop_heartbeat.session_environment", return_value=("KDE", "wayland")), patch("desktop_heartbeat.time.monotonic", side_effect=[1.0, 1.025]):
            self.assertEqual(desktop_heartbeat.kwin_ping(), (True, 25.0))

    @patch("desktop_heartbeat.subprocess.run")
    def test_ping_failure_returns_latency(self, run):
        run.return_value.returncode = 1
        with patch("desktop_heartbeat.session_environment", return_value=("KDE", "wayland")), patch("desktop_heartbeat.time.monotonic", side_effect=[1.0, 1.4]):
            self.assertEqual(desktop_heartbeat.kwin_ping(), (False, 400.0))

    def test_runtime_environment_has_user_bus_fallback(self):
        with patch.dict(os.environ, {"XDG_RUNTIME_DIR": "/run/user/1002"}, clear=True):
            env = desktop_heartbeat.runtime_environment()
        self.assertEqual(env["DBUS_SESSION_BUS_ADDRESS"], "unix:path=/run/user/1002/bus")
        self.assertEqual(env["WAYLAND_DISPLAY"], "wayland-0")


if __name__ == "__main__":
    unittest.main()