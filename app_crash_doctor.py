import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import hashlib
import json
from coredump_adapter import parse_systemd_coredump_json

# Default minimum unique-incident count before a recurring-crash issue is
# raised for an application. Fedora Crash Doctor is a generic diagnostic
# product and ships with no application-specific defaults; a user or site
# that wants a particular executable reported more eagerly (e.g. a
# known-fragile in-house tool) can lower its threshold via an optional,
# genuinely external config file -- see load_min_incident_overrides().
DEFAULT_MIN_INCIDENTS = 3


def app_crash_profile_path() -> Path:
    xdg_config = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return Path(xdg_config) / "fedora-crash-doctor" / "app_crash_profiles.json"


def load_min_incident_overrides(path: Path | None = None) -> dict[str, int]:
    """Load optional per-executable minimum-incident-count overrides from a
    user/site-editable JSON config file (default: app_crash_profile_path()).
    Format: {"executables": {"some-app": {"min_incidents": 1}}}.

    There is no built-in list of "special" applications: an executable is
    only reported below DEFAULT_MIN_INCIDENTS if this file says so. A
    missing or malformed file is treated as "no overrides" rather than an
    error, since a bad config file must never stop crash analysis from
    running.
    """
    path = path or app_crash_profile_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    overrides: dict[str, int] = {}
    for name, profile in (data.get("executables") or {}).items():
        if isinstance(profile, dict) and isinstance(profile.get("min_incidents"), int):
            overrides[name.lower()] = profile["min_incidents"]
    return overrides


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
    min_incident_overrides = load_min_incident_overrides()

    for app_name, evs in by_app.items():
        evs.sort(key=lambda x: x["time"].timestamp() if x["time"] else 0)
        total_count = len(evs)

        min_incidents = min_incident_overrides.get(app_name.lower(), DEFAULT_MIN_INCIDENTS)
        if total_count < min_incidents:
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
        
        # analyze_app_crashes() is a pure log-parsing function: it must never
        # itself launch GDB or touch the network. Symbolic analysis is a
        # separate, explicit action (see symbolic_analysis.start_symbolic_analysis)
        # -- here we only record enough identity for a caller to request it.
        backtrace = {"state": "unavailable"}
        if last['status'] == 'present' and str(last['pid']).isdigit():
            ts_str = str(int(last['time'].timestamp())) if last['time'] else "0"
            backtrace = {
                "state": "not_requested",
                "request": {"pid": str(last["pid"]), "executable": last["exe"], "timestamp": ts_str},
            }

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
                       timeout=60.0, output_limit=10 * 1024 * 1024,
                       cancel_event=None, allow_network=False):
    """Capture bounded debugger output; return a structured result to callers.

    This is a low-level, blocking worker that launches GDB via coredumpctl.
    Callers must never invoke this as a side effect of parsing/scanning --
    use symbolic_analysis.start_symbolic_analysis() instead, which makes
    that an explicit, bounded, cancellable, deduplicated job.

    allow_network defaults to False: symbolication then uses only debug
    info already present on this machine, and debuginfod is explicitly
    disabled -- any DEBUGINFOD_URLS inherited from the caller's environment
    is stripped so ambient configuration cannot silently turn network
    access back on. Pass allow_network=True only from a caller that has
    told the user Fedora's debuginfod service may be contacted to download
    debug symbols over the network; that is the only condition under which
    this function performs network activity.

    cancel_event, if given, is polled once per read cycle; setting it stops
    the wait loop the same way a timeout does and the debugger process tree
    is still killed via the existing cleanup path, just with state
    'cancelled' instead of 'timed_out'.
    """
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
        return {"state": "failed", "error": "Invalid incident identifier", "network_used": False}
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
        if allow_network:
            env["DEBUGINFOD_URLS"] = "https://debuginfod.fedoraproject.org/"
            debuginfod_setting = "on"
        else:
            # Strip any inherited DEBUGINFOD_URLS so ambient environment/config
            # cannot silently re-enable network access for a local-only request.
            env.pop("DEBUGINFOD_URLS", None)
            debuginfod_setting = "off"
        debugger_args = (
            '--batch -nx -iex "set auto-load off" '
            f'-iex "set debuginfod enabled {debuginfod_setting}" '
            '-ex "set pagination off" -ex "thread apply all bt full" -ex quit'
        )
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
                if cancel_event is not None and cancel_event.is_set():
                    state = "cancelled"
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    state = "timed_out"
                    break
                # Poll in short slices so a cancellation is noticed promptly
                # instead of only after the full remaining deadline.
                if not selector.select(min(remaining, 0.25)):
                    continue
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
        return {"state": state, "path": os.path.join(output_dir, name), "bytes": len(payload),
                "network_used": allow_network}
    except (OSError, ValueError) as exc:
        return {"state": "failed", "error": str(exc), "network_used": allow_network}
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
