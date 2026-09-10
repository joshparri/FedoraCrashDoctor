import re
from datetime import datetime, timezone
from typing import Any
import hashlib
import json
from coredump_adapter import parse_systemd_coredump_json

def parse_coredumpctl_line(line: str) -> dict[str, Any] | None:
    match = re.match(r"^\w{3}\s+(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\s+\w+\s+(\d+)\s+\d+\s+\d+\s+(\w+)\s+(\w+)\s+(\S+)\s+(.+)$", line.strip())
    if match:
        date_str = match.group(1)
        time_str = match.group(2)
        pid = match.group(3)
        sig = match.group(4)
        status = match.group(5)
        exe = match.group(6)
        size = match.group(7).strip()
        
        try:
            dt = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None
            
        return {
            "time": dt,
            "pid": pid,
            "signal": sig,
            "status": status,
            "exe": exe,
            "size": size,
            "raw": line
        }
    return None

def analyze_app_crashes(lines: list[str]) -> list[dict[str, Any]]:
    crashes = []
    raw_count = 0
    unique_crashes = {}
    
    # First pass: try to parse any structured JSON lines (new format)
    structured = parse_systemd_coredump_json(lines, resolve_packages=False)
    for incident in structured:
        # Convert to the internal representation used by this doctor
        dt = datetime.fromtimestamp(incident["timestamp"]) if incident["timestamp"] is not None else None
        
        ca = incident.get("core_available", "unknown")
        if ca is True:
            status = "present"
        elif ca is False:
            status = "missing"
        else:
            status = "unknown"
            
        parsed = {
            "time": dt,
            "pid": str(incident["pid"]) if incident["pid"] else "unknown",
            "signal": str(incident["signal"]) if incident["signal"] else "unknown",
            "status": status,
            "exe": incident["executable"] or "unknown",
            "size": "unknown",
            "raw": f"{incident['timestamp']} {incident['executable']}"
        }
        raw_count += 1
        boot_part = incident.get("boot_id") or "unknown_boot"
        time_part = parsed['time'].isoformat() if parsed['time'] else "unknown_time"
        eid = f"{boot_part}_{time_part}_{parsed['pid']}_{parsed['exe']}_{parsed['signal']}"
        if eid not in unique_crashes:
            unique_crashes[eid] = parsed
            crashes.append(parsed)
            
    for line in lines:
        if line.startswith("{"):
            continue # Already handled by parse_systemd_coredump_json
            
        parsed = parse_coredumpctl_line(line)
        if parsed:
            raw_count += 1
            # deduplicate by time, pid, exe, signal against ALL known crashes
            # since legacy lines don't have a boot_id, we just use a weak time-based check
            # if we already have a structured crash with this time/pid/exe/sig, skip it!
            time_str = parsed['time'].isoformat()
            
            # Check if this matches any existing crash
            matched = False
            for existing in crashes:
                if (existing['time'] == parsed['time'] and 
                    existing['pid'] == parsed['pid'] and 
                    existing['exe'] == parsed['exe'] and 
                    existing['signal'] == parsed['signal']):
                    matched = True
                    break
                    
            if not matched:
                eid = f"legacy_{time_str}_{parsed['pid']}_{parsed['exe']}_{parsed['signal']}"
                if eid not in unique_crashes:
                    unique_crashes[eid] = parsed
                    crashes.append(parsed)

    # Count raw appearances for each executable basename
    # We count from both structured and parsed legacy lines directly
    app_raw_counts = {}
    
    for incident in structured:
        if incident.get("executable"):
            app_name = incident["executable"].split("/")[-1]
            app_raw_counts[app_name] = app_raw_counts.get(app_name, 0) + 1
            
    for line in lines:
        if line.startswith("{"):
            continue
        p = parse_coredumpctl_line(line)
        if p:
            app_name = p["exe"].split("/")[-1]
            app_raw_counts[app_name] = app_raw_counts.get(app_name, 0) + 1

    by_app = {}
    for c in crashes:
        app_name = c["exe"].split("/")[-1]
        
        if app_name not in by_app:
            by_app[app_name] = []
        by_app[app_name].append(c)
        
    issues = []
    def create_issue(category, title, status, evidence, action):
        return {
            "category": category,
            "title": title,
            "status": status,
            "evidence": evidence,
            "recommended_action": action,
        }

    now = datetime.now()
    
    for app_name, evs in by_app.items():
        evs.sort(key=lambda x: x["time"].timestamp() if x["time"] else 0)
        total_count = len(evs)
        
        if total_count < 3 and "antigravity" not in app_name.lower():
            continue
            
        first_seen = evs[0]["time"]
        last_seen = evs[-1]["time"]
        
        today_crashes = [c for c in evs if c["time"] and (now - c["time"]).total_seconds() < 86400]
        
        paths = list(set(c["exe"] for c in evs))
        signals = list(set(c["signal"] for c in evs))
        
        last = evs[-1]
        
        evidence = [
            f"Unique incidents: {total_count}",
            f"Raw evidence appearances: {app_raw_counts.get(app_name, 0)}",
            f"Recent/current boot crashes: {len(today_crashes)}",
            f"First seen: {first_seen.strftime('%Y-%m-%d %H:%M:%S') if first_seen else 'Unknown'}",
            f"Last seen: {last_seen.strftime('%Y-%m-%d %H:%M:%S') if last_seen else 'Unknown'}",
            f"Most recent coredump: {last['status']} ({last['size']})",
            f"Signals observed: {', '.join(signals)}",
        ]
        
        backtrace = {"state": "unavailable"}
        if last['status'] == 'present' and str(last['pid']).isdigit():
            import threading
            ts_str = str(int(last['time'].timestamp())) if last['time'] else "0"
            backtrace["state"] = "running"

            def resolve(result=backtrace, pid=str(last["pid"]), exe=last["exe"], ts=ts_str):
                result.update(generate_backtrace(pid, exe, ts))

            t = threading.Thread(target=resolve, daemon=True)
            t.start()
            evidence.append("Symbolic backtrace resolution initiated in background.")

        if len(paths) > 1:
            evidence.append(f"Executable path changed across history: {', '.join(paths)}")
            
        issues.append(create_issue(
            "applications",
            f"Application instability: {app_name.capitalize()} has a recurring crash history.",
            "Warning",
            evidence,
            "Investigate application-specific logs, versions, or reinstall."
        ))
        issues[-1]["backtrace"] = backtrace
        
    return issues


def generate_backtrace(pid: str, executable: str, timestamp: str, *,
                       output_dir=None,
                       timeout=60.0, output_limit=10 * 1024 * 1024):
    """Capture bounded debugger output; return a structured result to callers."""
    import os
    import selectors
    import signal
    import subprocess
    import sys
    import time
    import stat
    import uuid

    if output_dir is None:
        output_dir = ("/var/log/fedora-crash-doctor/backtraces" if os.geteuid() == 0 else
                      os.path.join(os.path.expanduser("~/.local/state"),
                                   "fedora-crash-doctor", "backtraces"))

    if not pid.isdecimal() or not timestamp.isdecimal():
        return {"state": "failed", "error": "Invalid incident identifier"}
    proc = None
    directory_fd = None
    try:
        # Walk with directory descriptors so no path component can be a symlink.
        directory_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        components = os.path.abspath(output_dir).split("/")[1:]
        for component in components:
            try:
                os.mkdir(component, 0o700, dir_fd=directory_fd)
            except FileExistsError:
                pass
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        metadata = os.fstat(directory_fd)
        if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise PermissionError("Backtrace directory must be private and owned by the current user")
        env = os.environ.copy()
        env["DEBUGINFOD_URLS"] = "https://debuginfod.fedoraproject.org/"
        debugger_args = '--batch -nx -iex "set auto-load off" -iex "set debuginfod enabled on" -ex "set pagination off" -ex "thread apply all bt full" -ex quit'
        cmd = [sys.executable, os.path.abspath(__file__), "--backtrace-worker",
               "coredumpctl", "debug", pid, f"COREDUMP_EXE={executable}",
               f"--debugger-arguments={debugger_args}"]
        deadline = time.monotonic() + timeout
        proc = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, start_new_session=True)
        output = bytearray()
        state = "completed"
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    state = "timed_out"
                    break
                if not selector.select(remaining):
                    state = "timed_out"
                    break
                chunk = os.read(proc.stdout.fileno(), min(65536, output_limit - len(output)))
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) >= output_limit:
                    state = "truncated"
                    break
        if state == "completed":
            try:
                if proc.wait(timeout=max(0.001, deadline - time.monotonic())) != 0:
                    state = "failed"
            except subprocess.TimeoutExpired:
                state = "timed_out"
        name = f"{pid}_{timestamp}_{uuid.uuid4().hex}.txt"
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory_fd)
        header = f"Backtrace state: {state}\n".encode()
        payload = (header + output)[:output_limit]
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
        return {"state": state, "path": os.path.join(output_dir, name), "bytes": len(payload)}
    except (OSError, ValueError) as exc:
        return {"state": "failed", "error": str(exc)}
    finally:
        if proc is not None:
            # Kill descendants as well, even when the immediate wrapper has exited.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
            proc.stdout.close()
        if directory_fd is not None:
            os.close(directory_fd)


if __name__ == "__main__":
    import os
    import resource
    import sys
    if len(sys.argv) > 2 and sys.argv[1] == "--backtrace-worker":
        # Resource setup runs in a fresh interpreter, never a threaded preexec_fn.
        resource.setrlimit(resource.RLIMIT_AS, (1024 ** 3, 1024 ** 3))
        resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
        resource.setrlimit(resource.RLIMIT_FSIZE, (10 * 1024 ** 2, 10 * 1024 ** 2))
        os.execvp(sys.argv[2], sys.argv[2:])
