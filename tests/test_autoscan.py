import unittest
from unittest.mock import patch, MagicMock
from collector import previous_boot_ended_uncleanly

class AutoscanTests(unittest.TestCase):
    @patch("subprocess.run")
    def test_autoscan_ignores_older_crash(self, mock_run):
        # Boot -1 ended cleanly, but boot -4 was a crash.
        def fake_run(args, **kwargs):
            if "--list-boots" in args:
                mock = MagicMock()
                mock.stdout = "-1 abcdef0123456789abcdef0123456789\n"
                return mock
            if "-1" in args and "-n" in args:
                mock = MagicMock()
                mock.stdout = "systemd[1]: Shutting down."
                return mock
            return MagicMock()

        mock_run.side_effect = fake_run
        unclean, boot_id = previous_boot_ended_uncleanly()
        self.assertFalse(unclean)

    @patch("subprocess.run")
    def test_autoscan_detects_unclean_immediately_previous(self, mock_run):
        def fake_run(args, **kwargs):
            if "--list-boots" in args:
                mock = MagicMock()
                mock.stdout = "-1 abcdef0123456789abcdef0123456789\n"
                return mock
            if "-1" in args and "-n" in args:
                mock = MagicMock()
                mock.stdout = "some crash happened"
                return mock
            return MagicMock()

        mock_run.side_effect = fake_run
        unclean, boot_id = previous_boot_ended_uncleanly()
        self.assertTrue(unclean)

if __name__ == "__main__":
    unittest.main()
