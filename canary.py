#!/usr/bin/env python3
"""Low-write system heartbeat for post-freeze correlation.

Runs as root under systemd. Samples lightweight /proc and /sys metrics.
Adapts sampling frequency during memory/I-O pressure.
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

from safe_mitigation import evaluate_sample

LOG_DIR = Path("/var/log/fedora-crash-doctor")
LOG_FILE = LOG_DIR / "canary.log"
NORMAL_INTERVAL = 15
WARNING_INTERVAL = 5
CRITICAL_INTERVAL = 2
FSYNC_EVERY_NORMAL = 60
FSYNC_EVERY_PRESSURE = 10


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
        "swap_total_mb": values.get("SwapTotal", 0),
        "slab_mb": values.get("Slab", 0),
        "sreclaimable_mb": values.get("SReclaimable", 0),
        "sunreclaim_mb": values.get("SUnreclaim", 0),
        "dirty_mb": values.get("Dirty", 0),
        "writeback_mb": values.get("Writeback", 0),
        "anon_mb": values.get("Active(anon)", 0) + values.get("Inactive(anon)", 0),
        "file_mb": values.get("Active(file)", 0) + values.get("Inactive(file)", 0),
        "swapcached_mb": values.get("SwapCached", 0),
        "pagetables_mb": values.get("PageTables", 0),
    }


def vmstat() -> dict[str, int]:
    stats = {}
    keys = {"pgscan_kswapd", "pgscan_direct", "pgsteal_kswapd", "pgsteal_direct",
            "pswpin", "pswpout", "pgmajfault", "workingset_refault"}
    for line in read_text("/proc/vmstat").splitlines():
        bits = line.split()
        if len(bits) == 2:
            key = bits[0]
            if key in keys or any(key.startswith(k) for k in keys):
                stats[key] = int(bits[1])
    return stats


def diskstats() -> dict[str, dict[str, int]]:
    disks = {}
    for line in read_text("/proc/diskstats").splitlines():
        bits = line.split()
        if len(bits) >= 14:
            name = bits[2]
            if name.startswith("loop") or name.startswith("ram"):
                continue
            disks[name] = {
                "r_ios": int(bits[3]),
                "r_sectors": int(bits[5]),
                "w_ios": int(bits[7]),
                "w_sectors": int(bits[9]),
                "in_flight": int(bits[11]),
                "io_ticks": int(bits[12]),
            }
    return disks


def zram_stats() -> dict[str, dict[str, int]]:
    stats = {}
    for path in Path("/sys/block").glob("zram*"):
        try:
            name = path.name
            mm_stat = (path / "mm_stat").read_text().split()
            stats[name] = {
                "orig_bytes": int(mm_stat[0]),
                "compr_bytes": int(mm_stat[1]),
                "mem_used_bytes": int(mm_stat[2])
            }
        except Exception:
            pass
    return stats


def gather_processes() -> dict[str, Any]:
    processes = []
    blocked = []
    for pid_str in os.listdir("/proc"):
        if not pid_str.isdigit():
            continue
        try:
            pid = int(pid_str)
            status_text = read_text(f"/proc/{pid}/status")
            if not status_text: continue
            stat = read_text(f"/proc/{pid}/stat").split()
            cmdline = read_text(f"/proc/{pid}/cmdline").replace('\0', ' ').strip()

            rss = 0
            swap = 0
            anon = 0
            file_mem = 0
            ppid = 0
            state = stat[2]
            threads = int(stat[19]) if len(stat) > 19 else 1

            for line in status_text.splitlines():
                if line.startswith("VmRSS:"): rss = int(line.split()[1])
                elif line.startswith("VmSwap:"): swap = int(line.split()[1])
                elif line.startswith("RssAnon:"): anon = int(line.split()[1])
                elif line.startswith("RssFile:"): file_mem = int(line.split()[1])
                elif line.startswith("PPid:"): ppid = int(line.split()[1])

            name = stat[1].strip("()")

            if state == 'D':
                wchan = read_text(f"/proc/{pid}/wchan")
                blocked.append({
                    "pid": pid, "name": name, "cmd": cmdline[:60], "wchan": wchan
                })

            if rss == 0 and swap == 0:
                continue

            group = "Other"
            cmd_lower = cmdline.lower()
            if "google/chrome" in cmd_lower or "chrome --" in cmd_lower: group = "Google Chrome"
            elif "antigravity" in cmd_lower: group = "Antigravity"
            elif "vscode" in cmd_lower or "code-insiders" in cmd_lower: group = "VS Code"
            elif "plasmashell" in cmd_lower or "kwin" in cmd_lower: group = "Plasma / KWin"
            elif "node" in cmd_lower: group = "Node.js"
            elif "python" in cmd_lower: group = "Python"
            elif "java" in cmd_lower: group = "Java"
            elif "electron" in cmd_lower: group = "Electron App"

            processes.append({
                "pid": pid, "ppid": ppid, "name": name, "cmd": cmdline[:100],
                "rss_kb": rss, "swap_kb": swap, "anon_kb": anon, "file_kb": file_mem,
                "state": state, "threads": threads, "group": group
            })
        except Exception:
            pass

    processes.sort(key=lambda x: x["rss_kb"], reverse=True)
    top_rss = processes[:25]

    processes.sort(key=lambda x: x["swap_kb"], reverse=True)
    top_swap = processes[:25]

    groups = {}
    for p in processes:
        g = groups.setdefault(p["group"], {"rss_kb": 0, "swap_kb": 0, "count": 0})
        g["rss_kb"] += p["rss_kb"]
        g["swap_kb"] += p["swap_kb"]
        g["count"] += 1

    return {"top_rss": top_rss, "top_swap": top_swap, "groups": groups, "blocked": blocked}


def max_temp_c() -> float | None:
    temps = []
    for path in Path("/sys/class/thermal").glob("thermal_zone*/temp"):
        try:
            value = float(path.read_text().strip())
            if value > 1000: value /= 1000
            if -20 <= value <= 150: temps.append(value)
        except Exception: pass
    for path in Path("/sys/class/hwmon").glob("hwmon*/temp*_input"):
        try:
            value = float(path.read_text().strip()) / 1000
            if -20 <= value <= 150: temps.append(value)
        except Exception: pass
    return round(max(temps), 1) if temps else None


def average_cpu_mhz() -> float | None:
    values = []
    for path in Path("/sys/devices/system/cpu").glob("cpu[0-9]*/cpufreq/scaling_cur_freq"):
        try: values.append(float(path.read_text().strip()) / 1000)
        except Exception: pass
    return round(sum(values) / len(values), 1) if values else None


def desktop_heartbeat() -> dict[str, Any]:
    now = time.time()
    newest = None
    for path in Path("/run/user").glob("[0-9]*/fedora-crash-doctor/desktop-heartbeat.json"):
        try:
            data = json.loads(path.read_text())
            stamp = float(data.get("epoch", path.stat().st_mtime))
            if newest is None or stamp > newest[0]:
                newest = (stamp, data)
        except Exception: pass
    if not newest:
        return {"desktop_heartbeat_age_s": None, "kwin_ok": None}
    stamp, data = newest
    return {
        "desktop_heartbeat_age_s": round(max(0, now - stamp), 1),
        "kwin_ok": data.get("kwin_ok"),
        "plasmashell_ok": data.get("plasmashell_ok"),
        "desktop_session": data.get("session"),
    }


def sample() -> tuple[dict[str, Any], int]:
    load = read_text("/proc/loadavg").split()
    mem = memory()
    psi_cpu = read_psi("cpu")
    psi_mem = read_psi("memory")
    psi_io = read_psi("io")

    # Adaptive interval calculation
    mem_avail_pct = (mem["mem_available_mb"] / max(1, mem["mem_total_mb"])) * 100
    swap_used_pct = (mem["swap_used_mb"] / max(1, mem["swap_total_mb"])) * 100 if mem["swap_total_mb"] else 0
    io_some = psi_io.get("some_avg10", 0)
    mem_some = psi_mem.get("some_avg10", 0)

    interval = NORMAL_INTERVAL
    if mem_avail_pct < 10 or swap_used_pct > 90 or io_some > 40 or mem_some > 20:
        interval = CRITICAL_INTERVAL
    elif mem_avail_pct < 20 or swap_used_pct > 70 or io_some > 15 or mem_some > 10:
        interval = WARNING_INTERVAL

    row: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "epoch": time.time(),
        "boot_id": read_text("/proc/sys/kernel/random/boot_id"),
        "uptime_s": round(float(read_text("/proc/uptime", "0").split()[0]), 1),
        "load1": float(load[0]) if load else 0,
        "load5": float(load[1]) if len(load) > 1 else 0,
        "max_temp_c": max_temp_c(),
        "avg_cpu_mhz": average_cpu_mhz(),
        "memory": mem,
        "psi_cpu": psi_cpu,
        "psi_mem": psi_mem,
        "psi_io": psi_io,
        "vmstat": vmstat(),
        "diskstats": diskstats(),
        "zram": zram_stats(),
    }

    row.update(desktop_heartbeat())

    # Process scanning can be slightly heavy, but critical for diagnosis.
    row["processes"] = gather_processes()
    row["early_warning"] = evaluate_sample(row)

    return row, interval


def main() -> int:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(LOG_FILE, maxBytes=15 * 1024 * 1024, backupCount=3)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger = logging.getLogger("fcd-canary")
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)

    next_fsync = time.monotonic()

    while True:
        started = time.monotonic()
        try:
            data, interval = sample()
            logger.info(json.dumps(data, separators=(",", ":")))
            handler.flush()

            fsync_target = FSYNC_EVERY_NORMAL if interval == NORMAL_INTERVAL else FSYNC_EVERY_PRESSURE
            if time.monotonic() >= next_fsync:
                try:
                    os.fdatasync(handler.stream.fileno())
                except OSError:
                    pass
                next_fsync = time.monotonic() + fsync_target

        except Exception as exc:
            logger.info(json.dumps({"ts": datetime.now().isoformat(), "collector_error": str(exc)}))
            interval = NORMAL_INTERVAL

        delay = max(0.5, interval - (time.monotonic() - started))
        time.sleep(delay)


if __name__ == "__main__":
    raise SystemExit(main())
