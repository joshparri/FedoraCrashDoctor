# Report Schema

`report.schema.json` documents the Fedora Crash Doctor report contract used by
the collector, GUI, exports and historical compatibility tests.

Runtime validation is implemented in `report_schema.py` so the application does
not require the external `jsonschema` package.
