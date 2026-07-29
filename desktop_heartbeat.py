#!/usr/bin/env python3
"""Per-user desktop/KWin heartbeat consumed by the root system canary."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

INTERVAL = 5


def kwin_ping() -> bool | None:
    if os.environ.get("XDG_CURRENT_DESKTOP", "").lower().find("kde") < 0:
        return None
    try:
        proc = subprocess.run(
            ["gdbus", "call", "--session", "--dest", "org.kde.KWin", "--object-path", "/KWin", "--method", "org.freedesktop.DBus.Peer.Ping"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
            env=os.environ.copy(),
        )
        return proc.returncode == 0
    except Exception:
        return False


def atomic_write(path: Path, payload: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix="heartbeat-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(payload, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, 0o600)
        os.replace(name, path)
    finally:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass


def main() -> int:
    runtime = Path(os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}"))
    target = runtime / "fedora-crash-doctor" / "desktop-heartbeat.json"
    while True:
        payload = {
            "ts": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
            "epoch": time.time(),
            "kwin_ok": kwin_ping(),
            "session": os.environ.get("XDG_SESSION_TYPE", "unknown"),
            "desktop": os.environ.get("XDG_CURRENT_DESKTOP", "unknown"),
        }
        try:
            atomic_write(target, payload)
        except Exception:
            pass
        time.sleep(INTERVAL)


if __name__ == "__main__":
    raise SystemExit(main())
