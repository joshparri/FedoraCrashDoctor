#!/usr/bin/env python3
"""Low-write system heartbeat for post-freeze correlation.

Runs as root under systemd. It samples lightweight /proc and /sys metrics every
15 seconds, rotates at 8 MiB, and fsyncs once per minute rather than every sample.
"""
from __future__ import annotations

import json
import logging
from logging.handlers import RotatingFileHandler
import os
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

LOG_DIR = Path("/var/log/fedora-crash-doctor")
LOG_FILE = LOG_DIR / "canary.log"
INTERVAL = 15
FSYNC_EVERY = 60


def read_text(path: str, default: str = "") -> str:
    try:
        return Path(path).read_text(errors="replace").strip()
    except Exception:
        return default


def read_psi(name: str) -> dict[str, float]:
    text = read_text(f"/proc/pressure/{name}")
    result: dict[str, float] = {}
    for line in text.splitlines():
        bits = line.split()
        if not bits:
            continue
        prefix = bits[0]
        for bit in bits[1:]:
            if "=" not in bit:
                continue
            key, value = bit.split("=", 1)
            if key in {"avg10", "avg60"}:
                try:
                    result[f"{prefix}_{key}"] = float(value)
                except ValueError:
                    pass
    return result


def memory() -> dict[str, int]:
    values: dict[str, int] = {}
    for line in read_text("/proc/meminfo").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        match = re.search(r"(\d+)", value)
        if match:
            values[key] = int(match.group(1)) // 1024
    return {
        "mem_available_mb": values.get("MemAvailable", 0),
        "mem_total_mb": values.get("MemTotal", 0),
        "swap_used_mb": max(0, values.get("SwapTotal", 0) - values.get("SwapFree", 0)),
    }


def max_temp_c() -> float | None:
    temps = []
    for path in Path("/sys/class/thermal").glob("thermal_zone*/temp"):
        try:
            value = float(path.read_text().strip())
            if value > 1000:
                value /= 1000
            if -20 <= value <= 150:
                temps.append(value)
        except Exception:
            pass
    for path in Path("/sys/class/hwmon").glob("hwmon*/temp*_input"):
        try:
            value = float(path.read_text().strip()) / 1000
            if -20 <= value <= 150:
                temps.append(value)
        except Exception:
            pass
    return round(max(temps), 1) if temps else None


def average_cpu_mhz() -> float | None:
    values = []
    for path in Path("/sys/devices/system/cpu").glob("cpu[0-9]*/cpufreq/scaling_cur_freq"):
        try:
            values.append(float(path.read_text().strip()) / 1000)
        except Exception:
            pass
    return round(sum(values) / len(values), 1) if values else None


def gpu_metrics() -> dict[str, Any]:
    result: dict[str, Any] = {}
    for card in Path("/sys/class/drm").glob("card[0-9]*"):
        device = card / "device"
        candidates = {
            "gpu_busy_percent": device / "gpu_busy_percent",
            "gt_cur_freq_mhz": device / "gt_cur_freq_mhz",
            "gt_act_freq_mhz": device / "gt_act_freq_mhz",
        }
        for key, path in candidates.items():
            if path.exists():
                try:
                    result[f"{card.name}_{key}"] = float(path.read_text().strip())
                except Exception:
                    pass
    return result


def net_wireless() -> dict[str, Any]:
    result: dict[str, Any] = {}
    for line in read_text("/proc/net/wireless").splitlines()[2:]:
        if ":" not in line:
            continue
        iface, values = line.split(":", 1)
        bits = values.split()
        if len(bits) >= 3:
            result["wifi_interface"] = iface.strip()
            try:
                result["wifi_link"] = float(bits[1].strip("."))
                result["wifi_signal_dbm"] = float(bits[2].strip("."))
            except ValueError:
                pass
    return result


def display_state() -> dict[str, str]:
    result = {}
    for status in Path("/sys/class/drm").glob("card*-*/status"):
        try:
            result[status.parent.name] = status.read_text().strip()
        except Exception:
            pass
    return result


def desktop_heartbeat() -> dict[str, Any]:
    now = time.time()
    newest: tuple[float, dict[str, Any]] | None = None
    for path in Path("/run/user").glob("[0-9]*/fedora-crash-doctor/desktop-heartbeat.json"):
        try:
            data = json.loads(path.read_text())
            stamp = float(data.get("epoch", path.stat().st_mtime))
            if newest is None or stamp > newest[0]:
                newest = (stamp, data)
        except Exception:
            pass
    if not newest:
        return {"desktop_heartbeat_age_s": None, "kwin_ok": None}
    stamp, data = newest
    return {
        "desktop_heartbeat_age_s": round(max(0, now - stamp), 1),
        "kwin_ok": data.get("kwin_ok"),
        "desktop_session": data.get("session"),
    }


def top_processes() -> list[str]:
    try:
        proc = subprocess.run(
            ["ps", "-eo", "pid,comm,%cpu,%mem", "--sort=-%cpu"],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=3, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
        return proc.stdout.splitlines()[1:5]
    except Exception:
        return []


def sample(include_slow: bool) -> dict[str, Any]:
    load = read_text("/proc/loadavg").split()
    row: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "epoch": time.time(),
        "boot_id": read_text("/proc/sys/kernel/random/boot_id"),
        "uptime_s": round(float(read_text("/proc/uptime", "0").split()[0]), 1),
        "load1": float(load[0]) if load else 0,
        "load5": float(load[1]) if len(load) > 1 else 0,
        "max_temp_c": max_temp_c(),
        "avg_cpu_mhz": average_cpu_mhz(),
    }
    row.update(memory())
    for name in ("cpu", "memory", "io"):
        for key, value in read_psi(name).items():
            row[f"psi_{name}_{key}"] = value
    row.update(gpu_metrics())
    row.update(net_wireless())
    row.update(desktop_heartbeat())
    if include_slow:
        row["displays"] = display_state()
        row["top_processes"] = top_processes()
    return row


def main() -> int:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(LOG_FILE, maxBytes=8 * 1024 * 1024, backupCount=3)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger = logging.getLogger("fcd-canary")
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    next_fsync = time.monotonic() + FSYNC_EVERY
    count = 0
    while True:
        started = time.monotonic()
        try:
            logger.info(json.dumps(sample(include_slow=(count % 4 == 0)), separators=(",", ":")))
            handler.flush()
            if time.monotonic() >= next_fsync:
                try:
                    os.fdatasync(handler.stream.fileno())
                except OSError:
                    pass
                next_fsync = time.monotonic() + FSYNC_EVERY
        except Exception as exc:
            logger.info(json.dumps({"ts": datetime.now().isoformat(), "collector_error": str(exc)}))
        count += 1
        delay = max(1, INTERVAL - (time.monotonic() - started))
        time.sleep(delay)


if __name__ == "__main__":
    raise SystemExit(main())
