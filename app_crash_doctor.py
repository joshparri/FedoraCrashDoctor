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
        
        if last['status'] == 'present' and str(last['pid']).isdigit():
            import threading
            import subprocess
            import os
            import select
            
            def run_gdb(pid_str: str, exe_path: str, ts_str: str):
                env = os.environ.copy()
                env["DEBUGINFOD_URLS"] = "https://debuginfod.fedoraproject.org/"
                
                cmd = [
                    "coredumpctl", "gdb", pid_str,
                    "--batch",
                    "-ex", "set pagination off",
                    "-ex", "thread apply all bt full",
                    "-ex", "quit"
                ]
                
                try:
                    def set_limits():
                        import resource
                        resource.setrlimit(resource.RLIMIT_AS, (1024 * 1024 * 1024, 1024 * 1024 * 1024))
                        resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
                        resource.setrlimit(resource.RLIMIT_FSIZE, (10 * 1024 * 1024, 10 * 1024 * 1024))
                    
                    proc = subprocess.Popen(
                        cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, preexec_fn=set_limits
                    )
                    
                    output = b""
                    while True:
                        ready, _, _ = select.select([proc.stdout], [], [], 60.0)
                        if not ready:
                            proc.kill()
                            output += b"\n\n[TRUNCATED: GDB analysis timed out]"
                            break
                        chunk = proc.stdout.read(4096)
                        if not chunk:
                            break
                        output += chunk
                        if len(output) > 5 * 1024 * 1024:
                            proc.kill()
                            output += b"\n\n[TRUNCATED: Output exceeded 5MB limit]"
                            break
                    proc.wait(timeout=5)
                    
                    out_dir = "/var/log/fedora-crash-doctor/backtraces"
                    os.makedirs(out_dir, exist_ok=True, mode=0o700)
                    safe_exe = exe_path.split('/')[-1] if exe_path else 'unknown'
                    out_path = os.path.join(out_dir, f"{pid_str}_{safe_exe}_{ts_str}.txt")
                    with open(out_path, "wb") as f:
                        f.write(output)
                except Exception:
                    if 'proc' in locals() and proc.poll() is None:
                        proc.kill()

            ts_str = str(int(last['time'].timestamp())) if last['time'] else "0"
            t = threading.Thread(target=run_gdb, args=(str(last['pid']), last['exe'], ts_str), daemon=True)
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
        
    return issues
