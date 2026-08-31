#!/usr/bin/env python3
"""Read-only Chrome/Chromium live incident capture.

This module deliberately does not terminate processes or modify browser,
kernel, display, swap, or service configuration.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable


CHROME_NAMES = {"chrome", "google-chrome", "google-chrome-stable", "chromium", "chromium-browser"}
JOURNAL_FILES = (
    "oomd.txt", "chrome-journal.txt", "graphics-journal.txt", "desktop-journal.txt",
    "kernel-journal.txt", "coredumps.txt", "crashpad.txt", "displays.txt",
)
OOM_RE = re.compile(r"(?:systemd-oomd.*Killed|Out of memory: Killed process|oom-kill:)", re.I)
COMPOSITOR_RE = re.compile(r"CompositorAnimationObserver is active for too long", re.I)
TIMESTAMP_RE = re.compile(r"^(\d{4}-\d\d-\d\dT[^ ]+)")


def _run(command: list[str], timeout: float = 5.0) -> str:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        output = result.stdout
        if result.stderr:
            output += result.stderr
        return output
    except subprocess.TimeoutExpired:
        return f"[ERROR] collector timeout: {' '.join(command)}"
    except (FileNotFoundError, OSError) as exc:
        return f"[ERROR] collector unavailable: {exc}"


def _read(path: Path) -> str:
    try:
        return path.read_text(errors="replace")
    except OSError as exc:
        return f"[ERROR] {path}: {exc}"


def _parse_timestamp(line: str) -> datetime | None:
    match = TIMESTAMP_RE.search(line)
    if not match:
        return None
    try:
        return datetime.fromisoformat(match.group(1))
    except ValueError:
        return None


def _command_line(pid_dir: Path) -> str:
    try:
        raw = (pid_dir / "cmdline").read_bytes()
        return " ".join(part.decode(errors="replace") for part in raw.split(b"\0") if part)
    except OSError:
        return ""


def _process_record(pid_dir: Path) -> dict[str, Any] | None:
    command_line = _command_line(pid_dir)
    executable = command_line.split(" ", 1)[0].rsplit("/", 1)[-1] if command_line else ""
    if executable.lower() not in CHROME_NAMES and "google-chrome" not in command_line.lower():
        return None
    try:
        pid = int(pid_dir.name)
        status = _read(pid_dir / "status")
        values: dict[str, str] = {}
        for line in status.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                values[key] = value.strip().split()[0] if value.strip() else "0"
        stat_line = _read(pid_dir / "stat").strip()
        close = stat_line.rfind(")")
        stat_fields = stat_line[close + 2:].split() if close >= 0 else []
        wchan = _read(pid_dir / "wchan").strip()
        stat = stat_fields[0] if stat_fields else ""
        cpu_percent = None
        elapsed = None
        if len(stat_fields) > 19:
            ticks = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
            uptime = float(_read(Path("/proc/uptime")).split()[0])
            start_ticks = int(stat_fields[19])
            elapsed = max(0.0, uptime - (start_ticks / ticks))
            if elapsed:
                cpu_percent = ((int(stat_fields[11]) + int(stat_fields[12])) / ticks) / elapsed * 100
        return {
            "pid": pid,
            "ppid": int(values.get("PPid", "0")),
            "process_type": next((arg.split("=", 1)[1] for arg in command_line.split() if arg.startswith("--type=")), "browser"),
            "rss_bytes": int(values.get("VmRSS", "0")) * 1024,
            "vsz_bytes": int(values.get("VmSize", "0")) * 1024,
            "stat": stat,
            "wchan": wchan,
            "cpu_percent": round(cpu_percent, 2) if cpu_percent is not None else None,
            "elapsed": round(elapsed, 2) if elapsed is not None else None,
            "command_line": command_line,
        }
    except (ValueError, OSError):
        return None


def collect_chrome_processes() -> list[dict[str, Any]]:
    records = []
    for entry in Path("/proc").iterdir():
        if entry.name.isdigit():
            record = _process_record(entry)
            if record:
                records.append(record)
    return sorted(records, key=lambda item: item["rss_bytes"], reverse=True)


def _meminfo() -> dict[str, int]:
    values = {}
    for line in _read(Path("/proc/meminfo")).splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            parts = value.strip().split()
            if parts and parts[0].isdigit():
                values[key] = int(parts[0]) * (1024 if len(parts) > 1 and parts[1] == "kB" else 1)
    return values


def collect_memory() -> dict[str, Any]:
    mem = _meminfo()
    swap_total = mem.get("SwapTotal", 0)
    swap_free = mem.get("SwapFree", 0)
    swap_devices = []
    for line in _read(Path("/proc/swaps")).splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 5:
            swap_devices.append({"name": parts[0], "type": parts[1], "size_bytes": int(parts[2]) * 1024, "used_bytes": int(parts[3]) * 1024, "priority": int(parts[4])})
    return {
        "MemTotal_bytes": mem.get("MemTotal", 0),
        "MemAvailable_bytes": mem.get("MemAvailable", 0),
        "SwapTotal_bytes": swap_total,
        "SwapFree_bytes": swap_free,
        "SwapUsed_bytes": max(0, swap_total - swap_free),
        "swap_devices": swap_devices,
        "zram_devices": [item for item in swap_devices if item["name"].startswith("/dev/zram")],
        "disk_swap_devices": [item for item in swap_devices if not item["name"].startswith("/dev/zram")],
        "zramctl": _run(["zramctl"], 3),
        "psi_memory": _read(Path("/proc/pressure/memory")),
        "psi_io": _read(Path("/proc/pressure/io")),
        "psi_cpu": _read(Path("/proc/pressure/cpu")),
    }


def _cgroup_path(pid: int) -> Path | None:
    for line in _read(Path(f"/proc/{pid}/cgroup")).splitlines():
        if "::" in line:
            relative = line.split("::", 1)[1]
            path = Path("/sys/fs/cgroup") / relative.lstrip("/")
            return path if path.exists() else None
    return None


def collect_chrome_cgroups(processes: list[dict[str, Any]]) -> dict[str, Any]:
    paths = {_cgroup_path(item["pid"]) for item in processes}
    paths.discard(None)
    result: dict[str, Any] = {"cgroups": []}
    for path in sorted(paths, key=str):
        values: dict[str, str] = {"path": str(path)}
        for name in ("memory.current", "memory.swap.current", "memory.events", "memory.pressure", "memory.stat", "memory.max", "memory.swap.max"):
            values[name] = _read(path / name).strip()
        result["cgroups"].append(values)
    return result


def _journal(command: list[str]) -> str:
    return _run(command, 8)


def _chrome_profile_paths() -> list[Path]:
    home = Path.home()
    return [
        home / ".config/google-chrome/Crash Reports",
        home / ".config/chromium/Crash Reports",
        home / ".config/google-chrome/Crashpad",
        home / ".config/chromium/Crashpad",
    ]


def prune_capture_directories(base: Path | None = None, max_count: int = 20, max_bytes: int = 512 * 1024 * 1024) -> dict[str, int]:
    base = base or (Path.home() / ".local/share/FedoraCrashDoctor/captures")
    directories = sorted((path for path in base.glob("chrome-incident-*") if path.is_dir()), key=lambda path: path.stat().st_mtime, reverse=True)
    removed = 0
    bytes_removed = 0
    total_bytes = 0
    for index, directory in enumerate(directories):
        size = sum(item.stat().st_size for item in directory.rglob("*") if item.is_file())
        total_bytes += size
        if index >= max_count or total_bytes > max_bytes:
            import shutil
            shutil.rmtree(directory, ignore_errors=True)
            removed += 1
            bytes_removed += size
    return {"removed_directories": removed, "bytes_removed": bytes_removed}


def collect_crashpad(capture_time: datetime, home: Path | None = None) -> tuple[str, list[dict[str, Any]]]:
    records = []
    if home is not None:
        roots = [
            home / ".config/google-chrome/Crash Reports", home / ".config/chromium/Crash Reports",
            home / ".config/google-chrome/Crashpad", home / ".config/chromium/Crashpad",
        ]
    else:
        roots = _chrome_profile_paths()
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            try:
                if path.is_file():
                    stat = path.stat()
                    if datetime.fromtimestamp(stat.st_mtime, timezone.utc) >= capture_time - timedelta(hours=1):
                        crash_id = next((match.group(0) for match in [re.search(r"[0-9a-f]{8,}", path.name, re.I)] if match), None)
                        records.append({"file": str(path), "timestamp": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(), "size_bytes": stat.st_size, "crash_id": crash_id})
            except OSError:
                continue
    return "\n".join(json.dumps(item, sort_keys=True) for item in records), records


def classify_chrome_incident(summary: dict[str, Any], journals: dict[str, str]) -> list[dict[str, Any]]:
    classifications = []
    current_boot = summary.get("boot_id", "")
    capture_time = datetime.fromisoformat(summary["capture_time"])
    window_start = capture_time - timedelta(minutes=10)
    all_lines = "\n".join(journals.values())
    current_lines = []
    for line in all_lines.splitlines():
        timestamp = _parse_timestamp(line)
        if timestamp and window_start <= timestamp <= capture_time and (not current_boot or current_boot in line or "boot_id=" not in line):
            current_lines.append((timestamp, line))

    oom_lines = [line for _, line in current_lines if OOM_RE.search(line) and ("chrome" in line.lower() or "chromium" in line.lower() or "oomd" in line.lower())]
    if oom_lines:
        classifications.append({"type": "confirmed_oom_kill", "observation": "A current-boot bounded journal explicitly identifies an OOM kill associated with Chrome/Chromium.", "evidence": oom_lines})

    compositor_lines = [line for _, line in current_lines if COMPOSITOR_RE.search(line)]
    if compositor_lines:
        classifications.append({"type": "chrome_compositor_stall_observed", "observation": "Chrome logged a long-running CompositorAnimationObserver; this records a Chrome symptom only.", "evidence": compositor_lines})

    coredump_lines = [line for line in journals.get("coredumps", "").splitlines() if re.search(r"chrome|chromium|crashpad", line, re.I) and not re.search(r"No coredumps", line, re.I)]
    if coredump_lines:
        classifications.append({"type": "confirmed_process_crash", "observation": "coredumpctl lists a Chrome/Chromium/Crashpad coredump.", "evidence": coredump_lines})

    symptoms = [(time, line) for time, line in current_lines if COMPOSITOR_RE.search(line)]
    display_lines = [(time, line) for time, line in current_lines if re.search(r"i915|drm|kwin_wayland|GPU HANG|GPU reset", line, re.I)]
    for symptom_time, symptom_line in symptoms:
        if display_lines:
            nearest_time, nearest_line = min(display_lines, key=lambda item: abs((item[0] - symptom_time).total_seconds()))
            seconds = int(abs((nearest_time - symptom_time).total_seconds()))
            direction = "before" if nearest_time <= symptom_time else "after"
            classifications.append({"type": "display_stack_correlation", "observation": f"Display-stack event occurred {seconds} seconds {direction} Chrome symptom; this is correlation, not causation.", "evidence": [nearest_line, symptom_line]})

    if not any(item["type"] in {"confirmed_oom_kill", "confirmed_process_crash"} for item in classifications):
        if not display_lines:
            classifications.append({"type": "no_system_level_failure_found", "observation": "No current-window OOM, GPU hang/reset, KWin event, or storage fault was found; Chrome itself is not thereby proven healthy.", "evidence": []})
    return classifications


def capture_chrome_incident(
    runner: Callable[[list[str], float], str] = _run,
    home: Path | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    if home is None:
        home = Path.home()
    capture_time = now or datetime.now(timezone.utc)
    base = home / ".local/share/FedoraCrashDoctor/captures"
    base.mkdir(parents=True, exist_ok=True)
    stem = f"chrome-incident-{capture_time.strftime('%Y%m%d-%H%M%S-%f')}"
    capture_dir = base / stem
    suffix = 0
    while True:
        try:
            capture_dir.mkdir(mode=0o700)
            break
        except FileExistsError:
            suffix += 1
            capture_dir = base / f"{stem}-{suffix:03d}"

    boot_id = _read(Path("/proc/sys/kernel/random/boot_id")).strip()
    processes = collect_chrome_processes()
    memory = collect_memory()
    identity = {
        "capture_time": capture_time.isoformat(), "boot_id": boot_id,
        "session_id": os.environ.get("XDG_SESSION_ID", "unknown"),
        "session_type": os.environ.get("XDG_SESSION_TYPE", "unknown"),
        "kernel": runner(["uname", "-r"], 3).strip(),
        "plasma_version": runner(["plasmashell", "--version"], 3).strip(),
        "kwin_version": runner(["kwin_wayland", "--version"], 3).strip(),
        "chrome_version": runner(["google-chrome", "--version"], 3).strip(),
        "chromium_version": runner(["chromium", "--version"], 3).strip(),
        "mesa_version": runner(["rpm", "-q", "mesa-dri-drivers"], 3).strip(),
        "intel_gpu": runner(["lspci", "-Dnnk"], 5),
    }
    command_lines = "\n".join(f"PID {item['pid']}: {item['command_line']}" for item in processes)
    process_text = "\n".join(json.dumps(item, sort_keys=True) for item in processes)
    cgroups = collect_chrome_cgroups(processes)
    since_arg = (capture_time - timedelta(minutes=10)).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    system_journal = runner(["journalctl", "-b", "0", f"--since={since_arg}", "--output=short-iso-precise", "--no-pager"], 8)
    user_journal = runner(["journalctl", "--user", "-b", "0", f"--since={since_arg}", "--output=short-iso-precise", "--no-pager"], 8)
    oomd = runner(["journalctl", "-u", "systemd-oomd", "-b", "0", f"--since={since_arg}", "--output=short-iso-precise", "--no-pager"], 8)
    coredumps = runner(["coredumpctl", "list", "-b", "0", "--no-pager"], 8)
    crashpad_text, crashpad_records = collect_crashpad(capture_time, home)
    journals = {
        "oomd": oomd,
        "chrome": "\n".join(line for line in system_journal.splitlines() if re.search(r"chrome|chromium|crashpad|CompositorAnimationObserver", line, re.I)),
        "graphics": "\n".join(line for line in system_journal.splitlines() if re.search(r"i915|drm|GPU HANG|GPU reset", line, re.I)),
        "desktop": "\n".join(line for line in (system_journal + "\n" + user_journal).splitlines() if re.search(r"kwin_wayland|plasmashell|kscreen|dbus", line, re.I)),
        "kernel": "\n".join(line for line in system_journal.splitlines() if "kernel" in line or "systemd-coredump" in line),
        "coredumps": coredumps,
    }
    summary: dict[str, Any] = {
        **identity,
        "chrome_process_count": len(processes),
        "chrome_aggregate_rss_bytes": sum(item["rss_bytes"] for item in processes),
        "chrome_aggregate_rss_note": "Aggregate RSS may double-count shared pages and is not exact unique physical RAM.",
        "largest_chrome_processes": processes[:10],
        "memory": memory,
        "cgroups": cgroups,
        "chrome_gpu_mode_evidence": [item["command_line"] for item in processes if any(flag in item["command_line"] for flag in ("--disable-gpu", "--disable-gpu-compositing", "--ozone-platform", "--use-gl", "--use-vulkan"))],
        "crashpad_records": crashpad_records,
        "capture_complete": True,
        "failed_collectors": [],
    }
    summary["classifications"] = classify_chrome_incident(summary, journals)
    files = {
        "summary.txt": json.dumps(summary, indent=2, sort_keys=True),
        "chrome-processes.txt": process_text,
        "chrome-cgroups.txt": json.dumps(cgroups, indent=2, sort_keys=True),
        "chrome-command-lines.txt": command_lines,
        "memory.txt": json.dumps(memory, indent=2, sort_keys=True),
        "oomd.txt": oomd,
        "chrome-journal.txt": journals["chrome"],
        "graphics-journal.txt": journals["graphics"],
        "desktop-journal.txt": journals["desktop"],
        "kernel-journal.txt": journals["kernel"],
        "coredumps.txt": coredumps,
        "crashpad.txt": crashpad_text,
        "displays.txt": runner(["kscreen-doctor", "-o"], 4),
    }
    for name, content in files.items():
        output_path = capture_dir / name
        output_path.write_text(content, encoding="utf-8")
        output_path.chmod(0o600)
        if content.startswith("[ERROR]"):
            summary["failed_collectors"].append(name)
    summary["capture_path"] = str(capture_dir)
    summary_path = capture_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    summary_path.chmod(0o600)
    prune_capture_directories(base)
    return summary


def main() -> None:
    result = capture_chrome_incident()
    print(f"Capture path: {result['capture_path']}")
    for item in result.get("classifications", []):
        print(f"{item['type']}: {item['observation']}")


if __name__ == "__main__":
    main()