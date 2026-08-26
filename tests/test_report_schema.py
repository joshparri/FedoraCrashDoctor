#!/usr/bin/env python3
import sys
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from collector import collect
from report_schema import REPORT_SCHEMA_VERSION, migrate_report, validate_report


class ReportSchemaTests(unittest.TestCase):
    def test_quick_report_conforms(self):
        report = collect("quick")
        validate_report(report)
        self.assertEqual(report["schema_version"], REPORT_SCHEMA_VERSION)

    def test_json_schema_document_is_valid_json(self):
        schema = json.loads((ROOT / "schema" / "report.schema.json").read_text())
        self.assertEqual(schema["properties"]["schema_version"]["const"], REPORT_SCHEMA_VERSION)

    def test_cancelled_report_conforms_and_marks_remaining_tasks(self):
        calls = {"count": 0}

        def cancel_after_first() -> bool:
            calls["count"] += 1
            return calls["count"] > 1

        report = collect("quick", cancel_requested=cancel_after_first)
        validate_report(report)
        self.assertTrue(report["partial"])
        self.assertTrue(report["cancelled"])
        states = {check["state"] for check in report["checks"].values()}
        self.assertIn("cancelled", states)

    def test_unknown_future_fields_do_not_break_reader(self):
        report = collect("quick")
        report["future_field"] = {"kept": True}
        validate_report(report, allow_future_fields=True)

    def test_older_report_is_migrated(self):
        report = collect("quick")
        report.pop("schema_version")
        migrated = migrate_report(report)
        self.assertEqual(migrated["schema_version"], REPORT_SCHEMA_VERSION)
        validate_report(migrated)


if __name__ == "__main__":
    unittest.main()
