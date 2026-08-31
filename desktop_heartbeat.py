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


def session_environment() -> tuple[str, str]:
    desktop = os.environ.get("XDG_CURRENT_DESKTOP", "")
    session_type = os.environ.get("XDG_SESSION_TYPE", "")
    if not desktop or not session_type:
        try:
            result = subprocess.run(
                ["loginctl", "show-session", os.environ.get("XDG_SESSION_ID", ""), "-p", "Type", "-p", "Desktop"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=2, text=True,
            )
            for line in result.stdout.splitlines():
                key, _, value = line.partition("=")
                if key == "Type" and not session_type:
                    session_type = value
                elif key == "Desktop" and not desktop:
                    desktop = value
        except Exception:
            pass
    return desktop or "unknown", session_type or "unknown"


def runtime_environment() -> dict[str, str]:
    env = os.environ.copy()
    env.setdefault("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
    env.setdefault("DBUS_SESSION_BUS_ADDRESS", f"unix:path={env['XDG_RUNTIME_DIR']}/bus")
    env.setdefault("WAYLAND_DISPLAY", "wayland-0")
    return env


def kwin_ping() -> tuple[bool | None, float | None]:
    desktop, _session_type = session_environment()
    if "kde" not in desktop.lower() and desktop != "unknown":
        return None, None
    started = time.monotonic()
    try:
        proc = subprocess.run(
            ["gdbus", "call", "--session", "--dest", "org.kde.KWin", "--object-path", "/KWin", "--method", "org.freedesktop.DBus.Peer.Ping"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
            env=runtime_environment(),
        )
        return proc.returncode == 0, round((time.monotonic() - started) * 1000, 2)
    except Exception:
        return False, round((time.monotonic() - started) * 1000, 2)


def process_present(name: str) -> bool:
    proc_dir = Path("/proc")
    for path in proc_dir.iterdir():
        if not path.name.isdigit():
            continue
        try:
            comm = (path / "comm").read_text(errors="replace").strip()
            if comm == name:
                return True
        except Exception:
            pass
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
    consecutive_failures = 0
    while True:
        desktop, session_type = session_environment()
        kwin_ok, kwin_ping_ms = kwin_ping()
        consecutive_failures = consecutive_failures + 1 if kwin_ok is False else 0
        payload = {
            "ts": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
            "epoch": time.time(),
            "kwin_ok": kwin_ok,
            "kwin_ping_ms": kwin_ping_ms,
            "kwin_consecutive_failures": consecutive_failures,
            "plasmashell_ok": process_present("plasmashell"),
            "session": session_type,
            "desktop": desktop,
        }
        try:
            atomic_write(target, payload)
        except Exception:
            pass
        time.sleep(INTERVAL)


if __name__ == "__main__":
    raise SystemExit(main())
