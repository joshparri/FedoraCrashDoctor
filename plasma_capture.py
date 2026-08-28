#!/usr/bin/env python3
import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import sys

def _run(cmd: list[str], timeout: float = 3.0, capture_stderr: bool = False) -> str:
    try:
        stderr = subprocess.STDOUT if capture_stderr else subprocess.DEVNULL
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=stderr, timeout=timeout, text=True)
        return res.stdout
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] Command exceeded {timeout} seconds"
    except FileNotFoundError:
        return f"[ERROR] Command not found: {cmd[0]}"
    except Exception as e:
        return f"[ERROR] Failed to run command: {e}"

def get_plasmashell_pid() -> int:
    out = _run(["systemctl", "--user", "show", "--property=MainPID", "--value", "plasma-plasmashell.service"])
    try:
        pid = int(out.strip())
        return pid if pid > 0 else 0
    except ValueError:
        return 0

def get_kwin_pid() -> int:
    out = _run(["pgrep", "-x", "kwin_wayland"])
    try:
        lines = out.strip().split()
        if lines:
            return int(lines[0])
    except ValueError:
        pass
    return 0

def capture_frozen_plasma() -> dict[str, Any]:
    start_time = datetime.now(timezone.utc)
    # Using microseconds to avoid directory collisions, with deterministic suffix retry
    ts = start_time.strftime("%Y%m%d-%H%M%S-%f")
    base_dir = Path.home() / ".local" / "share" / "FedoraCrashDoctor" / "captures"
    base_dir.mkdir(parents=True, exist_ok=True)

    capture_dir = base_dir / f"plasma-freeze-{ts}"
    suffix = 0
    while True:
        try:
            capture_dir.mkdir(parents=False, exist_ok=False)
            break
        except FileExistsError:
            suffix += 1
            capture_dir = base_dir / f"plasma-freeze-{ts}-{suffix:03d}"

    summary: dict[str, Any] = {
        "capture_time": start_time.isoformat(),
        "capture_complete": False,
        "failed_collectors": [],
    }

    def save(name: str, content: str, empty_is_failure: bool = True) -> None:
        if content or not empty_is_failure:
            with open(capture_dir / name, "w", encoding="utf-8") as f:
                f.write(content)
        else:
            summary["failed_collectors"].append(name)

    def read_file(path: str) -> str:
        try:
            return Path(path).read_text(errors='replace').strip()
        except OSError as e:
            return f"[ERROR] {e}"

    # 1. Identity / timestamp
    identity = [
        f"Date: {_run(['date', '-Is']).strip()}",
        f"Hostname: {_run(['hostname']).strip()}",
        f"Kernel: {_run(['uname', '-r']).strip()}",
        f"Boot ID: {read_file('/proc/sys/kernel/random/boot_id')}",
        f"Cmdline: {read_file('/proc/cmdline')}",
    ]
    summary["boot_id"] = identity[3]

    session_id = os.environ.get("XDG_SESSION_ID", read_file('/proc/self/sessionid'))
    session_type = os.environ.get("XDG_SESSION_TYPE", "Unknown")
    identity.append(f"Session ID: {session_id}")
    identity.append(f"Session Type: {session_type}")
    summary["session_id"] = session_id
    summary["session_type"] = session_type

    save("summary.txt", "\n".join(identity))

    # 2. Memory / load
    mem_info = [
        "--- free -h ---", _run(["free", "-h"]),
        "--- swapon ---", _run(["swapon", "--show"]),
        "--- uptime ---", _run(["uptime"]),
        "--- memory pressure ---", read_file("/proc/pressure/memory"),
        "--- cpu pressure ---", read_file("/proc/pressure/cpu"),
        "--- io pressure ---", read_file("/proc/pressure/io"),
    ]

    free_out = mem_info[1]
    if free_out and "Mem:" in free_out:
        parts = free_out.split("Mem:")[1].strip().split()
        if len(parts) >= 6:
            summary["memory_available"] = parts[5]

    swap_out = mem_info[3]
    if swap_out and len(swap_out.splitlines()) > 1:
        summary["swap_used"] = "Yes"
    else:
        summary["swap_used"] = "No"

    save("memory.txt", "\n".join(mem_info))

    # 3. Plasma service
    service_props = _run(["systemctl", "--user", "show", "plasma-plasmashell.service"])
    save("plasma-service.txt", service_props + "\n\n--- STATUS ---\n" + _run(["systemctl", "--user", "status", "plasma-plasmashell.service", "--no-pager", "-l"]))

    for line in service_props.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            if k in ["ActiveState", "SubState", "MainPID"]:
                summary[f"plasmashell_{k.lower()}"] = v

    plasma_pid = get_plasmashell_pid()
    summary["plasmashell_pid"] = plasma_pid
    summary["plasmashell_process_present"] = (plasma_pid > 0)

    # 4. plasmashell process
    if plasma_pid > 0:
        ps_out = _run(["ps", "-p", str(plasma_pid), "-o", "pid,ppid,stat,wchan:40,pcpu,pmem,comm,etime"])
        save("plasmashell-process.txt", ps_out)

        if len(ps_out.splitlines()) > 1:
            parts = ps_out.splitlines()[1].split()
            if len(parts) >= 4:
                summary["plasmashell_stat"] = parts[2]
                summary["plasmashell_wchan"] = parts[3]

        threads_out = _run(["ps", "-L", "-p", str(plasma_pid), "-o", "pid,tid,ppid,stat,wchan:40,pcpu,pmem,comm"])
        save("plasmashell-threads.txt", threads_out)

        try:
            fd_list = []
            for fd_path in Path(f"/proc/{plasma_pid}/fd").iterdir():
                try:
                    fd_list.append(f"{fd_path.name} -> {fd_path.readlink()}")
                except OSError:
                    pass
            save("plasmashell-fds.txt", "\n".join(fd_list))
        except OSError:
            summary["failed_collectors"].append("plasmashell-fds")

        save("plasmashell-lsof.txt", _run(["lsof", "-nP", "-p", str(plasma_pid)], timeout=5.0))

        # threads stack without shell commands
        try:
            stacks = []
            for tid_dir in Path(f"/proc/{plasma_pid}/task").iterdir():
                if not tid_dir.name.isdigit(): continue
                stack_file = tid_dir / "stack"
                try:
                    stacks.append(f"--- TID {tid_dir.name} ---\n{stack_file.read_text(errors='replace')}")
                except OSError as e:
                    stacks.append(f"--- TID {tid_dir.name} ---\n[ERROR] {e}")
            save("plasmashell-stacks.txt", "\n\n".join(stacks))
        except OSError:
            summary["failed_collectors"].append("plasmashell-stacks")

    # 5. KWin
    kwin_pid = get_kwin_pid()
    summary["kwin_pid"] = kwin_pid
    if kwin_pid > 0:
        save("kwin-process.txt", _run(["ps", "-p", str(kwin_pid), "-o", "pid,ppid,stat,wchan:40,pcpu,pmem,comm,etime"]))
        save("kwin-threads.txt", _run(["ps", "-L", "-p", str(kwin_pid), "-o", "pid,tid,ppid,stat,wchan:40,pcpu,pmem,comm"]))

    # 6. D-Bus (using gdbus)
    dbus_probe_cmd = [
        "gdbus", "call", "--session",
        "--dest", "org.kde.plasmashell",
        "--object-path", "/PlasmaShell",
        "--method", "org.kde.PlasmaShell.evaluateScript",
        'print("PANELS=" + panels().length);'
    ]
    summary["dbus_probe_tool"] = "gdbus"
    summary["dbus_probe_target"] = "org.kde.plasmashell"

    try:
        dbus_res = subprocess.run(dbus_probe_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=4.0, text=True)
        summary["dbus_probe_stdout"] = dbus_res.stdout
        summary["dbus_probe_stderr"] = dbus_res.stderr
        summary["dbus_probe_exit_code"] = dbus_res.returncode
        summary["dbus_probe_timed_out"] = False
        if dbus_res.returncode == 0:
            summary["dbus_probe_status"] = "success"
        else:
            summary["dbus_probe_status"] = "error"
    except subprocess.TimeoutExpired as e:
        summary["dbus_probe_stdout"] = e.stdout.decode(errors='replace') if isinstance(e.stdout, bytes) else (e.stdout or "")
        summary["dbus_probe_stderr"] = e.stderr.decode(errors='replace') if isinstance(e.stderr, bytes) else (e.stderr or "")
        summary["dbus_probe_exit_code"] = -1
        summary["dbus_probe_timed_out"] = True
        summary["dbus_probe_status"] = "timeout"
    except FileNotFoundError:
        summary["dbus_probe_stdout"] = ""
        summary["dbus_probe_stderr"] = "gdbus not found"
        summary["dbus_probe_exit_code"] = -1
        summary["dbus_probe_timed_out"] = False
        summary["dbus_probe_status"] = "command-unavailable"
    except Exception as e:
        summary["dbus_probe_stdout"] = ""
        summary["dbus_probe_stderr"] = str(e)
        summary["dbus_probe_exit_code"] = -1
        summary["dbus_probe_timed_out"] = False
        summary["dbus_probe_status"] = "service-unavailable"

    save("dbus-probe.txt", (
        f"Command: {' '.join(dbus_probe_cmd)}\n"
        f"Status: {summary['dbus_probe_status']}\n"
        f"Exit code: {summary['dbus_probe_exit_code']}\n"
        f"Stdout: {summary['dbus_probe_stdout']}\n"
        f"Stderr: {summary['dbus_probe_stderr']}\n"
    ))

    # 7. Displays
    kscreen_out = _run(["kscreen-doctor", "-o"], timeout=4.0)
    save("displays.txt", kscreen_out)
    summary["display_output_count"] = kscreen_out.count("Output:")

    drm_status = ""
    try:
        for conn in Path("/sys/class/drm").glob("card*-*"):
            try:
                status = (conn / "status").read_text().strip()
                drm_status += f"{conn.name}: {status}\n"
            except OSError:
                pass
    except OSError:
        pass
    save("drm-connectors.txt", drm_status)

    # 8. Journals
    since = (start_time.timestamp() - 600)
    since_str = datetime.fromtimestamp(since).strftime("%Y-%m-%d %H:%M:%S")
    journal_cmd = ["journalctl", f"--since={since_str}", "--output=short-iso", "--no-pager"]

    graphics_units = ["i915", "kwin_wayland", "plasmashell", "kscreen", "dbus", "systemd-coredump"]

    recent_full = _run(journal_cmd, timeout=8.0)
    save("recent-journal.txt", recent_full)

    graphics_journal = "\n".join(line for line in recent_full.splitlines() if any(u in line for u in graphics_units) or "drm" in line.lower())
    save("graphics-journal.txt", graphics_journal, empty_is_failure=False)

    summary["i915_atomic_event_in_recent_window"] = "Atomic update failure" in graphics_journal
    summary["gpu_hang_in_recent_window"] = "GPU HANG" in graphics_journal
    summary["gpu_reset_in_recent_window"] = "reset" in graphics_journal.lower()

    # 9. Related desktop services
    services_out = _run(["systemctl", "--user", "status", "dbus-broker.service", "pipewire.service", "wireplumber.service", "--no-pager"])
    save("desktop-services.txt", services_out)

    summary["capture_complete"] = True

    with open(capture_dir / "summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    summary["capture_path"] = str(capture_dir)
    return summary

def main():
    print("Capturing frozen Plasma evidence...")
    res = capture_frozen_plasma()
    print(f"Capture path: {res.get('capture_path')}")
    failed = res.get("failed_collectors", [])
    if failed:
        print(f"Partial failures: {', '.join(failed)}")
    print("Done.")

if __name__ == "__main__":
    main()
