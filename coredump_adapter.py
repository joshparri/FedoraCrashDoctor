import json
import hashlib
import subprocess
from typing import Any, Optional

def _get_package_info(executable: str) -> dict[str, str]:
    if not executable or not executable.startswith("/"):
        return {}
    
    try:
        # Query RPM for the package owning the file
        result = subprocess.run(
            ["rpm", "-qf", "--queryformat", "%{NAME}\\n%{VERSION}-%{RELEASE}\\n%{ARCH}", executable],
            capture_output=True,
            text=True,
            timeout=2
        )
        if result.returncode == 0:
            lines = result.stdout.strip().split("\\n")
            if len(lines) == 3:
                return {
                    "package": lines[0],
                    "package_version": lines[1],
                    "architecture": lines[2],
                }
    except Exception:
        pass
    return {}

def parse_systemd_coredump_json(lines: list[str], resolve_packages: bool = True) -> list[dict[str, Any]]:
    """Parse structured JSON lines from journalctl -t systemd-coredump -o json"""
    incidents = []
    
    # Cache package info to avoid redundant rpm calls
    pkg_cache = {}
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
            
        # Ignore entries that aren't actual coredumps (e.g., just general log messages)
        # Usually they have COREDUMP_PID or MESSAGE="Process... dumped core."
        if "COREDUMP_PID" not in entry and "COREDUMP_EXE" not in entry:
            continue
            
        exe = entry.get("COREDUMP_EXE") or entry.get("_EXE")
        
        incident = {
            "incident_source": "systemd-coredump",
            "boot_id": entry.get("_BOOT_ID"),
            "timestamp": int(entry.get("__REALTIME_TIMESTAMP", 0)) / 1000000.0 if "__REALTIME_TIMESTAMP" in entry else None,
            "pid": int(entry.get("COREDUMP_PID")) if entry.get("COREDUMP_PID") else None,
            "uid": int(entry.get("COREDUMP_UID")) if entry.get("COREDUMP_UID") else None,
            "gid": int(entry.get("COREDUMP_GID")) if entry.get("COREDUMP_GID") else None,
            "signal": int(entry.get("COREDUMP_SIGNAL")) if entry.get("COREDUMP_SIGNAL") else None,
            "signal_name": entry.get("COREDUMP_SIGNAL_NAME"),
            "executable": exe,
            "command": entry.get("COREDUMP_CMDLINE"),
            "comm": entry.get("COREDUMP_COMM"),
            "unit": entry.get("COREDUMP_UNIT") or entry.get("_SYSTEMD_UNIT"),
            "user_unit": entry.get("COREDUMP_USER_UNIT"),
            "hostname": entry.get("_HOSTNAME"),
            
            "storage": {
                "present": "COREDUMP_FILENAME" in entry,
                "location": entry.get("COREDUMP_FILENAME"),
            },
            
            "core_available": "COREDUMP_FILENAME" in entry,
            "metadata_available": True,
            "journal_cursor": entry.get("__CURSOR"),
            
            "package": None,
            "package_version": None,
            "architecture": None,
            "build_id": None,
        }
        
        # We can extract build_id if it's in the metadata. (Often systemd-coredump doesn't expose it directly in the journal, but we can leave it None and populate later if we do symbolisation).
        
        if resolve_packages and exe:
            if exe not in pkg_cache:
                pkg_cache[exe] = _get_package_info(exe)
            
            pkg_info = pkg_cache[exe]
            incident.update(pkg_info)
            
        raw_hash = hashlib.sha256(line.encode("utf-8")).hexdigest()
        incident["raw_source_hash"] = raw_hash
        
        incidents.append(incident)
        
    return incidents

def get_systemd_coredumps(since: str = "30 days ago") -> list[dict[str, Any]]:
    """Fetch structured coredump evidence directly from the systemd journal."""
    try:
        result = subprocess.run(
            ["journalctl", "-t", "systemd-coredump", "-o", "json", "--since", since],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            lines = result.stdout.strip().split("\\n")
            return parse_systemd_coredump_json(lines)
    except Exception:
        pass
    
    return []
