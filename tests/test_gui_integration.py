import unittest
import sys
import os
import json
from unittest.mock import patch, MagicMock

# Ensure we can import fedora_crash_doctor
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

class RealGuiIntegrationTests(unittest.TestCase):
    def test_gui_loads_full_report_without_errors(self):
        # Only run this test if we are executing with offscreen platform
        if os.environ.get("QT_QPA_PLATFORM") != "offscreen":
            self.skipTest("Requires QT_QPA_PLATFORM=offscreen")
            
        from PySide6.QtWidgets import QApplication
        from fedora_crash_doctor import MainWindow
        import collector
        from tests.test_analysis import check
        
        # Create a QApplication instance if one doesn't exist
        app = QApplication.instance()
        if app is None:
            app = QApplication(sys.argv)
            
        # Create dummy full evidence
        checks = {
            "previous_errors": check("prev", "2026-07-29T12:21:00+1000 host kernel: i915 atomic update failure\
2026-07-29T12:21:00+1000 host kernel: Out of memory: Killed process"),
            "boot_history": check("boot", "reboot   system boot  7.1.5-200.fc44.x Wed Jul 29 12:26 - crash  (03:25)"),
            "journal_boots": check("boots", "-1 e2110b7c6f7e4e72afca6dfe736dbfb8 Wed 2026-07-29 12:00:00 AEST Wed 2026-07-29 12:26:00 AEST\
0 e2110b7c6f7e4e72afca6dfe736dbfb8 Wed 2026-07-29 12:26:01 AEST Wed 2026-07-29 13:26:00 AEST")
        }
        
        # Collect report
        collector.get_evidence = MagicMock(return_value=checks)
        report = collector.collect("quick")
        report_json = json.loads(json.dumps(report, default=str))
        
        # Instantiate MainWindow
        window = MainWindow()
        
        # Load the report
        window.report = report_json
        
        # Invoke population paths
        try:
            window.populate_hypotheses()
            window.populate_findings()
            window.populate_fixes()
            window.populate_timeline()
            window.populate_checks()
        except Exception as e:
            self.fail(f"GUI population failed with exception: {e}")
            
if __name__ == "__main__":
    unittest.main()
