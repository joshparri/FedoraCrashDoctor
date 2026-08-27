import re
from datetime import datetime, timedelta, timezone
from typing import Any

OOMD_KILL_RE = re.compile(
    r"Killed (.*?) due to memory used \((\d+)\) / total \((\d+)\) and swap used \((\d+)\) / total \((\d+)\) being more than ([\d\.]+)%"
)

def normalize_app_name(cgroup: str) -> str:
    cgroup_lower = cgroup.lower()
    if "chrome" in cgroup_lower or "chromium" in cgroup_lower:
        if "chromium" in cgroup_lower: return "Chromium"
        return "Chrome"
    if "firefox" in cgroup_lower: return "Firefox"
    if "teams" in cgroup_lower: return "Teams"
    if "zoom" in cgroup_lower: return "Zoom"
    if "slack" in cgroup_lower: return "Slack"
    if "plasma" in cgroup_lower or "kde" in cgroup_lower or "kwin" in cgroup_lower: return "KDE/Plasma"
    if "code" in cgroup_lower or "idea" in cgroup_lower: return "IDE"
    return cgroup.split("/")[-1]

def is_interactive(app_name: str) -> bool:
    return app_name in ["Chrome", "Chromium", "Firefox", "Teams", "Zoom", "Slack", "KDE/Plasma", "IDE"]

def parse_journal_timestamp(line: str) -> datetime | None:
    # Handle ISO 8601 from --output=short-iso e.g. 2026-08-27T15:51:41+1000
    parts = line.split()
    if not parts:
        return None
    try:
        dt_str = parts[0]
        return datetime.fromisoformat(dt_str)
    except ValueError:
        pass
    
    # Fallback to syslog style (without year) - just in case
    if len(parts) >= 3:
        try:
            month, day, time_str = parts[0], parts[1], parts[2]
            year = datetime.now().year
            dt = datetime.strptime(f"{year} {month} {day} {time_str}", "%Y %b %d %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return None

def parse_systemd_oomd_events(journal_output: str) -> list[dict[str, Any]]:
    events = []
    lines = journal_output.splitlines()
    for i, line in enumerate(lines):
        match = OOMD_KILL_RE.search(line)
        if match:
            dt = parse_journal_timestamp(line)
            cgroup = match.group(1)
            system_mem_used = int(match.group(2))
            system_mem_total = int(match.group(3))
            system_swap_used = int(match.group(4))
            system_swap_total = int(match.group(5))
            limit = float(match.group(6))
            
            app_name = normalize_app_name(cgroup)
            interactive = is_interactive(app_name)
            
            victim_swap = "unknown"
            # Extract victim swap from the preceding lines
            for j in range(max(0, i - 15), i):
                prev_line = lines[j]
                if cgroup in prev_line and j + 1 < i:
                    next_line = lines[j + 1]
                    if "Swap Usage:" in next_line:
                        victim_swap = next_line.split("Swap Usage:")[1].strip()
                        break
            
            events.append({
                "timestamp": dt,
                "timestamp_str": dt.isoformat() if dt else line[:15],
                "cgroup": cgroup,
                "app_name": app_name,
                "system_mem_used": system_mem_used,
                "system_mem_total": system_mem_total,
                "system_swap_used": system_swap_used,
                "system_swap_total": system_swap_total,
                "system_swap_percent": (system_swap_used / max(1, system_swap_total)) * 100,
                "limit": limit,
                "victim_swap_usage": victim_swap,
                "interactive": interactive,
                "raw": line
            })
                    
    return events

def analyze_oom_events(events: list[dict[str, Any]], zram_only: bool, has_disk_swap: bool = False) -> list[dict[str, Any]]:
    issues = []
    if not events:
        return issues
        
    def create_issue(category, title, status, evidence, action):
        return {
            "category": category,
            "title": title,
            "status": status,
            "evidence": evidence,
            "recommended_action": action,
        }

    now = datetime.now(timezone.utc)
    
    # Fix year wrap-around for non-iso fallback
    for e in events:
        if e["timestamp"]:
            if e["timestamp"] > now + timedelta(days=1):
                e["timestamp"] = e["timestamp"].replace(year=e["timestamp"].year - 1)
            
    events = sorted([e for e in events if e["timestamp"]], key=lambda x: x["timestamp"])
    
    recent_events = [e for e in events if (now - e["timestamp"]).total_seconds() <= 3600]
    
    historical_clusters = []
    current_cluster = []
    for e in events:
        if not current_cluster:
            current_cluster.append(e)
        else:
            if (e["timestamp"] - current_cluster[-1]["timestamp"]).total_seconds() <= 3600:
                current_cluster.append(e)
            else:
                if len(current_cluster) >= 2:
                    historical_clusters.append(current_cluster)
                current_cluster = [e]
    if len(current_cluster) >= 2:
        historical_clusters.append(current_cluster)
        
    recent_repeated = len(recent_events) >= 2
    
    # Process historical
    for cluster in historical_clusters:
        if cluster == current_cluster and recent_repeated:
            continue # Handled by recent
        
        minutes = int((cluster[-1]["timestamp"] - cluster[0]["timestamp"]).total_seconds() / 60)
        date_str = cluster[0]["timestamp"].strftime("%d %b %Y")
        issues.append(create_issue(
            "memory",
            f"Historical incident: {len(cluster)} OOM kills within {minutes} minutes on {date_str}",
            "Historical",
            [f"Victims: {', '.join(set(e['app_name'] for e in cluster))}"],
            "Review if this was resolved by subsequent fixes."
        ))

    # Process recent
    if recent_repeated:
        minutes = int((recent_events[-1]["timestamp"] - recent_events[0]["timestamp"]).total_seconds() / 60)
        victims = ", ".join(list(set(e["app_name"] for e in recent_events)))
        last_event = recent_events[-1]
        
        evidence = [
            f"{len(recent_events)} OOM kills occurred within {minutes} minutes recently.",
            f"Victims include: {victims}",
            f"System swap reached {last_event['system_swap_percent']:.1f}%."
        ]
        
        if last_event['victim_swap_usage'] != "unknown":
            evidence.append(f"{last_event['app_name']} consumed ~{last_event['victim_swap_usage']} swap and was selected as the victim.")
            
        if zram_only and not has_disk_swap:
            evidence.append("Only zram swap is configured.")
            issues.append(create_issue(
                "memory",
                "CONFIRMED: Repeated systemd-oomd kills caused by swap exhaustion",
                "Critical — Repeated OOM kills are disrupting desktop applications",
                evidence,
                "Add lower-priority disk-backed emergency swap; retain systemd-oomd protection."
            ))
        elif has_disk_swap:
            issues.append(create_issue(
                "memory",
                "MITIGATED: 16 GiB lower-priority disk-backed swap is now configured and active.",
                "Mitigated",
                evidence,
                "Continue monitoring to see if the fallback swap resolves the pressure."
            ))
        else:
            issues.append(create_issue(
                "memory",
                "CONFIRMED: Repeated systemd-oomd kills caused by swap exhaustion",
                "Critical",
                evidence,
                "Review memory usage and swap configuration."
            ))
    elif recent_events:
        last_event = recent_events[-1]
        evidence = [
            f"Time: {last_event['timestamp_str']}",
            f"Victim: {last_event['app_name']}",
            f"System swap utilisation: {last_event['system_swap_used'] / (1024**3):.1f} GiB / {last_event['system_swap_total'] / (1024**3):.1f} GiB",
        ]
        if last_event['victim_swap_usage'] != "unknown":
            evidence.append(f"Victim swap usage: {last_event['victim_swap_usage']}")
            
        issues.append(create_issue(
            "memory",
            "Application killed because swap headroom was exhausted",
            "Warning",
            evidence,
            "Check if this becomes a repeated issue."
        ))

    if zram_only and not has_disk_swap and not issues:
        issues.append(create_issue(
            "memory",
            "Zram-only swap configuration",
            "Monitoring",
            ["Swap consists solely of /dev/zram*", "No disk-backed fallback exists"],
            "If freezes occur, configure a disk-backed swapfile."
        ))
        
    return issues
