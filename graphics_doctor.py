import re
from datetime import datetime, timezone
from typing import Any
import hashlib

def parse_iso_time(timestamp_str: str) -> datetime | None:
    try:
        return datetime.fromisoformat(timestamp_str)
    except ValueError:
        return None

def extract_timestamp(line: str) -> datetime | None:
    parts = line.split()
    if not parts:
        return None
    return parse_iso_time(parts[0])

def cluster_events(events: list[dict[str, Any]], window_seconds: int = 60) -> list[list[dict[str, Any]]]:
    if not events:
        return []
    clusters = []
    current_cluster = [events[0]]
    for e in events[1:]:
        if (e["time"] - current_cluster[-1]["time"]).total_seconds() <= window_seconds:
            current_cluster.append(e)
        else:
            clusters.append(current_cluster)
            current_cluster = [e]
    clusters.append(current_cluster)
    return clusters

def generate_event_id(dt: datetime, normalized_msg: str) -> str:
    # Stable identity: timestamp (up to second) + normalized message
    base = f"{dt.replace(microsecond=0).isoformat()}_{normalized_msg}"
    return hashlib.md5(base.encode()).hexdigest()

def analyze_graphics_events(lines: list[str]) -> list[dict[str, Any]]:
    raw_i915 = []
    raw_kwin = []
    raw_plasma = []
    raw_kscreen = []
    
    unique_i915 = {}
    unique_kwin = {}
    unique_plasma = {}
    unique_kscreen = {}
    
    now = datetime.now(timezone.utc)
    
    for line in lines:
        dt = extract_timestamp(line)
        if not dt:
            continue
            
        if "i915" in line and ("Atomic update failure" in line or "GPU HANG" in line or "reset" in line.lower() or "*ERROR*" in line):
            raw_i915.append(line)
            # Normalize message (remove exact scanline numbers, time us)
            norm = re.sub(r"\(start=\d+ end=\d+\)|time \d+ us|min \d+|max \d+|scanline start \d+|end \d+", "", line)
            norm = re.sub(r"AVANCE-WS7.*?kernel: ", "", norm)
            eid = generate_event_id(dt, norm)
            if eid not in unique_i915:
                unique_i915[eid] = {"time": dt, "raw": line, "norm": norm}
                
        elif "kwin_wayland" in line and ("Applying output configuration failed" in line or "Invalid framebuffer status" in line):
            raw_kwin.append(line)
            norm = re.sub(r"\[\d+\]", "", line.split("kwin_wayland", 1)[-1])
            eid = generate_event_id(dt, norm)
            if eid not in unique_kwin:
                unique_kwin[eid] = {"time": dt, "raw": line}
                
        elif "plasmashell" in line and "crash" in line.lower():
            raw_plasma.append(line)
            norm = re.sub(r"\[\d+\]", "", line.split("plasmashell", 1)[-1])
            eid = generate_event_id(dt, norm)
            if eid not in unique_plasma:
                unique_plasma[eid] = {"time": dt, "raw": line}
                
        elif "kscreen-doctor" in line and "crash" in line.lower():
            raw_kscreen.append(line)
            norm = re.sub(r"\[\d+\]", "", line.split("kscreen-doctor", 1)[-1])
            eid = generate_event_id(dt, norm)
            if eid not in unique_kscreen:
                unique_kscreen[eid] = {"time": dt, "raw": line}

    i915_events = sorted(unique_i915.values(), key=lambda x: x["time"])
    
    current_boot_i915 = []
    historical_i915 = []
    
    if i915_events:
        last_event_time = i915_events[-1]["time"]
        for e in i915_events:
            if (now - e["time"]).total_seconds() < 3600 * 24: # Proximate for current boot
                current_boot_i915.append(e)
            else:
                historical_i915.append(e)

    issues = []
    
    def create_issue(category, title, status, evidence, action):
        return {
            "category": category,
            "title": title,
            "status": status,
            "evidence": evidence,
            "recommended_action": action,
        }
        
    if current_boot_i915:
        clusters = cluster_events(current_boot_i915)
        issues.append(create_issue(
            "graphics",
            "Recurring Intel display pipeline errors are present in the current boot.",
            "Recurring",
            [f"Incident clusters: {len(clusters)}", f"Unique events: {len(current_boot_i915)}", f"Raw evidence appearances: {len([l for l in raw_i915 if (now - extract_timestamp(l)).total_seconds() < 3600*24])}"],
            "Temporarily run one monitor, use one refresh rate, disable fractional scaling, or test alternate cable/port."
        ))
        
    if historical_i915:
        clusters = cluster_events(historical_i915 + current_boot_i915)
        issues.append(create_issue(
            "graphics",
            f"{len(clusters)} i915 atomic update error clusters were found across the available history.",
            "Historical",
            [f"Incident clusters: {len(clusters)}", f"Unique events: {len(historical_i915) + len(current_boot_i915)}", f"Raw evidence appearances: {len(raw_i915)}", f"First seen: {i915_events[0]['time']}", f"Last seen: {i915_events[-1]['time']}"],
            "Review if recent kernel/Mesa updates have resolved these."
        ))
        
    if unique_plasma:
        issues.append(create_issue(
            "graphics",
            "Desktop component crash: plasmashell",
            "Warning",
            [f"Unique incidents: {len(unique_plasma)}", f"Raw evidence appearances: {len(raw_plasma)}"],
            "Check KDE bug trackers for known plasmashell issues with current Mesa/Intel drivers."
        ))
        
    if unique_kwin:
        issues.append(create_issue(
            "graphics",
            "Desktop component crash: kwin_wayland",
            "Warning",
            [f"Unique incidents: {len(unique_kwin)}", f"Raw evidence appearances: {len(raw_kwin)}"],
            "Test Wayland with simplified display configuration (single monitor, standard refresh rate)."
        ))
        
    if unique_kscreen:
        issues.append(create_issue(
            "graphics",
            "Desktop component crash: kscreen-doctor",
            "Warning",
            [f"Unique incidents: {len(unique_kscreen)}", f"Raw evidence appearances: {len(raw_kscreen)}"],
            "Check for display configuration conflicts."
        ))
        
    return issues
