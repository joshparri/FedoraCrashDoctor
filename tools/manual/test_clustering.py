import json, re
from datetime import datetime, timedelta
from collector import get_boot_for_ts, parse_boots_from_journal, build_incidents

f = json.load(open('real_scan_2.json'))
incidents = build_incidents(f['findings'], f['checks'])
print(json.dumps(incidents, indent=2))
