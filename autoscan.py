#!/usr/bin/env python3
"""Boot-time quick scan after an unclean previous shutdown."""
from __future__ import annotations

import json
import os
import pwd
import re
import subprocess
import sys
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(APP_DIR))
from collector import collect  # noqa: E402

CONFIG = Path("/etc/fedora-crash-doctor/owner.json")
STATE = Path("/var/lib/fedora-crash-doctor")


def run(args: list[str]) -> str:
    try:
        return subprocess.run(
            args, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=60, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C.UTF-8"}
        ).stdout
    except Exception:
        return ""


def unclean_previous_boot() -> bool:
    history = run(["last", "-x", "-n", "30"])
    if re.search(r"\s-crash\s|\bcrash\s+\(", history):
        return True
    current = run(["journalctl", "-b", "0", "--no-pager", "-n", "500"])
    return bool(re.search(r"uncleanly shut down|journal.*corrupt", current, re.I))


def main() -> int:
    if os.geteuid() != 0 or not CONFIG.exists() or not unclean_previous_boot():
        return 0
    try:
        owner = json.loads(CONFIG.read_text())
        uid, gid = int(owner["uid"]), int(owner["gid"])
        pwd.getpwuid(uid)
    except Exception:
        return 1

    baseline = STATE / "baselines" / str(uid) / "latest.json"
    report = collect("quick", str(baseline) if baseline.exists() else None)

    out_dir = STATE / "autoscans" / str(uid)
    out_dir.mkdir(parents=True, exist_ok=True)
    os.chown(out_dir, uid, gid)
    os.chmod(out_dir, 0o700)
    output = out_dir / "latest.json"
    tmp = out_dir / ".latest.json.tmp"
    tmp.write_text(json.dumps(report, ensure_ascii=False))
    os.chown(tmp, uid, gid)
    os.chmod(tmp, 0o600)
    tmp.replace(output)

    base_dir = STATE / "baselines" / str(uid)
    base_dir.mkdir(parents=True, exist_ok=True)
    base = base_dir / "latest.json"
    base_tmp = base_dir / ".latest.json.tmp"
    base_tmp.write_text(json.dumps(report, ensure_ascii=False))
    os.chmod(base_tmp, 0o600)
    base_tmp.replace(base)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
