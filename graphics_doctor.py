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
    base = f"{dt.replace(microsecond=0).isoformat()}_{normalized_msg}"
    return hashlib.md5(base.encode()).hexdigest()

def analyze_graphics_events(
    lines: list[str],
    user_symptom_times: list[datetime] = None,
    user_hotplug_times: list[datetime] = None,
    current_boot_start: datetime = None,
    current_boot_id: str = None,
    explicit_dbus_timeouts: list[datetime] = None
) -> list[dict[str, Any]]:
    raw_i915 = []
    raw_kwin = []
    raw_plasma = []
    raw_kscreen = []

    unique_i915 = {}
    unique_kwin = {}
    unique_plasma = {}
    unique_kscreen = {}
    unique_connector_warn = {}
    unique_plasma_timeout = {}
    unique_dbus_timeout = {}

    now = datetime.now(timezone.utc)

    for line in lines:
        dt = extract_timestamp(line)
        if not dt:
            continue
        boot_id = None
        boot_match = re.search(r"_BOOT_ID=([a-f0-9]+)", line)
        if boot_match:
            boot_id = boot_match.group(1)

        if "i915" in line and ("Atomic update failure" in line or "GPU HANG" in line or "reset" in line.lower() or "*ERROR*" in line):
            raw_i915.append(line)
            norm = re.sub(r"\(start=\d+ end=\d+\)|time \d+ us|min \d+|max \d+|scanline start \d+|end \d+", "", line)
            norm = re.sub(r"AVANCE-WS7.*?kernel: ", "", norm)
            eid = generate_event_id(dt, norm)
            if eid not in unique_i915:
                unique_i915[eid] = {"time": dt, "raw": line, "norm": norm, "boot_id": boot_id, "raw_count": 1}
            else:
                unique_i915[eid]["raw_count"] += 1

        elif "kwin_wayland" in line:
            raw_kwin.append(line)
            norm = re.sub(r"\[\d+\]", "", line.split("kwin_wayland", 1)[-1])
            eid = generate_event_id(dt, norm)
            if eid not in unique_kwin:
                unique_kwin[eid] = {"time": dt, "raw": line}

        elif "State 'stop-sigterm' timed out" in line and "plasma-plasmashell" in line:
            eid = generate_event_id(dt, "plasma-sigterm-timeout")
            if eid not in unique_plasma_timeout:
                unique_plasma_timeout[eid] = {"time": dt, "raw": line}

        elif "plasmashell" in line:
            raw_plasma.append(line)
            norm = re.sub(r"\[\d+\]", "", line.split("plasmashell", 1)[-1])
            eid = generate_event_id(dt, norm)
            if eid not in unique_plasma:
                unique_plasma[eid] = {"time": dt, "raw": line}

        elif "kscreen-doctor" in line:
            raw_kscreen.append(line)
            norm = re.sub(r"\[\d+\]", "", line.split("kscreen-doctor", 1)[-1])
            eid = generate_event_id(dt, norm)
            if eid not in unique_kscreen:
                unique_kscreen[eid] = {"time": dt, "raw": line}

        elif "Bad link status detected on connector" in line:
            norm = line.split("Bad link status detected on connector", 1)[-1].strip()
            eid = generate_event_id(dt, norm)
            if eid not in unique_connector_warn:
                unique_connector_warn[eid] = {"time": dt, "raw": line, "connector": norm}


        elif "WaitForName: Service was not registered within timeout" in line or ("kded6" in line and "reply timeout expired" in line):
            eid = generate_event_id(dt, "desktop-dbus-timeout")
            if eid not in unique_dbus_timeout:
                unique_dbus_timeout[eid] = {"time": dt, "raw": line}

    i915_events = sorted(unique_i915.values(), key=lambda x: x["time"])

    kwin_list = sorted(unique_kwin.values(), key=lambda x: x["time"])
    plasma_list = sorted(unique_plasma.values(), key=lambda x: x["time"])

    current_boot_i915 = []
    historical_i915 = []
    unknown_boot_i915 = []

    def calc_stats(ev_list):
        p = {"A": 0, "B": 0, "C": 0, "Unknown": 0}
        at, hg, rs, corr = 0, 0, 0, 0
        for e in ev_list:
            if "pipe A" in e["raw"]: p["A"] += 1
            elif "pipe B" in e["raw"]: p["B"] += 1
            elif "pipe C" in e["raw"]: p["C"] += 1
            else: p["Unknown"] += 1

            if "Atomic update failure" in e["raw"]: at += 1
            if "GPU HANG" in e["raw"]: hg += 1
            if "reset" in e["raw"].lower(): rs += 1

            kwin_near = any(abs((k["time"] - e["time"]).total_seconds()) <= 30 for k in kwin_list)
            plasma_near = any(abs((p["time"] - e["time"]).total_seconds()) <= 30 for p in plasma_list)
            if user_symptom_times and any(abs((s - e["time"]).total_seconds()) <= 30 for s in user_symptom_times):
                e["user_visible_symptom_correlated"] = True
            if kwin_near or plasma_near or e.get("user_visible_symptom_correlated"):
                corr += 1
        return p, at, hg, rs, corr

    for e in i915_events:
        if current_boot_id and e.get("boot_id") == current_boot_id:
            e["boot_status"] = "current"
        elif current_boot_id and e.get("boot_id") != current_boot_id and e.get("boot_id"):
            e["boot_status"] = "historical"
        elif current_boot_start:
            if e["time"] >= current_boot_start:
                e["boot_status"] = "current"
            else:
                e["boot_status"] = "historical"
        else:
            e["boot_status"] = "unknown"

        if e["boot_status"] == "current":
            current_boot_i915.append(e)
        elif e["boot_status"] == "historical":
            historical_i915.append(e)
        else:
            unknown_boot_i915.append(e)




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
        p, at, hg, rs, corr = calc_stats(current_boot_i915)
        evidence = [
            f"Incident clusters: {len(clusters)}",
            f"Unique events: {len(current_boot_i915)}",
            f"Raw evidence appearances: {sum(e['raw_count'] for e in current_boot_i915)}",
            f"Pipe A: {p['A']} | Pipe B: {p['B']} | Pipe C: {p['C']} | Unknown: {p['Unknown']}",
            f"Atomic Failures: {at} | Hangs: {hg} | Resets: {rs}",
            f"Component Correlation: {corr} events correlated, {len(current_boot_i915) - corr} uncorrelated"
        ]
        user_visible = sum(1 for e in current_boot_i915 if e.get("user_visible_symptom_correlated"))
        if user_visible > 0:
            evidence.append(f"User-visible symptoms explicitly correlated: {user_visible}")
        issues.append(create_issue(
            "graphics",
            "Recurring Intel display pipeline errors are present in the current boot.",
            "Recurring",
            evidence,
            "Temporarily run one monitor, use one refresh rate, disable fractional scaling, or test alternate cable/port."
        ))

    if historical_i915:
        clusters = cluster_events(historical_i915)
        p, at, hg, rs, corr = calc_stats(historical_i915)
        evidence = [
            f"Incident clusters: {len(clusters)}",
            f"Unique events: {len(historical_i915)}",
            f"Raw evidence appearances: {sum(e['raw_count'] for e in historical_i915)}",
            f"Pipe A: {p['A']} | Pipe B: {p['B']} | Pipe C: {p['C']} | Unknown: {p['Unknown']}",
            f"Atomic Timing Failures: {at} | GPU Hangs: {hg} | GPU Resets: {rs}",
            f"Desktop Component Correlation (±30s): {corr} events correlated, {len(historical_i915) - corr} uncorrelated",
        ]

        user_visible = sum(1 for e in i915_events if e.get("user_visible_symptom_correlated"))
        if user_visible > 0:
            evidence.append(f"User-visible symptoms explicitly correlated: {user_visible}")

        if historical_i915:
            evidence.append(f"First seen: {i915_events[0]['time']}")
            evidence.append(f"Last seen: {i915_events[-1]['time']}")

        issues.append(create_issue(
            "graphics",
            f"{len(clusters)} i915 atomic update error clusters were found across the available history.",
            "Historical",
            evidence,
            "Review if recent kernel/Mesa updates have resolved these."
        ))

    if unknown_boot_i915:
        clusters = cluster_events(unknown_boot_i915)
        p, at, hg, rs, corr = calc_stats(unknown_boot_i915)
        evidence = [
            f"Unique events: {len(unknown_boot_i915)}",
            f"Raw evidence appearances: {sum(e['raw_count'] for e in unknown_boot_i915)}",
            f"Pipe A: {p['A']} | Pipe B: {p['B']} | Pipe C: {p['C']} | Unknown: {p['Unknown']}",
            f"Atomic Failures: {at} | Hangs: {hg} | Resets: {rs}"
        ]
        user_visible = sum(1 for e in unknown_boot_i915 if e.get("user_visible_symptom_correlated"))
        if user_visible > 0:
            evidence.append(f"User-visible symptoms explicitly correlated: {user_visible}")
        issues.append(create_issue(
            "graphics",
            f"{len(clusters)} i915 atomic update error clusters were found with unknown boot context.",
            "Unknown Boot",
            evidence,
            "Review if recent kernel/Mesa updates have resolved these."
        ))

    all_hangs = sum(1 for e in i915_events if "GPU HANG" in e["raw"])
    all_resets = sum(1 for e in i915_events if "reset" in e["raw"].lower())
    if all_hangs > 0 or all_resets > 0:
        issues.append(create_issue(
            "graphics",
            "Actual GPU HANG or RESET events detected.",
            "Warning",
            [f"GPU Hangs: {all_hangs}", f"GPU Resets: {all_resets}"],
            "Investigate i915 hardware crash. Distinct from atomic timing faults."
        ))

    if [e for e in unique_plasma.values() if "crash" in e["raw"].lower()]:
        issues.append(create_issue(
            "graphics",
            "Desktop component crash: plasmashell",
            "Warning",
            [f"Unique incidents: {len([e for e in unique_plasma.values() if 'crash' in e['raw'].lower()])}"],
            "Check KDE bug trackers for known plasmashell issues with current Mesa/Intel drivers."
        ))

    if [e for e in unique_kwin.values() if "crash" in e["raw"].lower() or "Applying output configuration failed" in e["raw"] or "Invalid framebuffer status" in e["raw"]]:
        issues.append(create_issue(
            "graphics",
            "Desktop component crash/fault: kwin_wayland",
            "Warning",
            [f"Unique incidents: {len([e for e in unique_kwin.values() if 'crash' in e['raw'].lower() or 'Applying' in e['raw'] or 'Invalid' in e['raw']])}"],
            "Test Wayland with simplified display configuration (single monitor, standard refresh rate)."
        ))

    if [e for e in unique_kscreen.values() if "crash" in e["raw"].lower()]:
        issues.append(create_issue(
            "graphics",
            "Desktop component crash: kscreen-doctor",
            "Warning",
            [f"Unique incidents: {len([e for e in unique_kscreen.values() if 'crash' in e['raw'].lower()])}"],
            "Check for display hotplug bugs."
        ))

    if unique_connector_warn:
        hotplug_correlated = []
        spontaneous = []
        unknown_context = []

        for e in unique_connector_warn.values():
            if user_hotplug_times and any(abs((h - e["time"]).total_seconds()) <= 30 for h in user_hotplug_times):
                hotplug_correlated.append(e)
            elif user_hotplug_times is not None:
                spontaneous.append(e)
            else:
                unknown_context.append(e)

        if hotplug_correlated:
            issues.append(create_issue(
                "graphics",
                "Connector warning correlated with explicit manual hotplug",
                "Info",
                [f"Unique incidents: {len(hotplug_correlated)}"],
                "Correlated with an explicitly recorded manual hotplug; do not treat this event as evidence of spontaneous link instability."
            ))

        if spontaneous:
            issues.append(create_issue(
                "graphics",
                "Spontaneous display link instability (Bad link status)",
                "Warning",
                [f"Unique incidents: {len(spontaneous)}", f"Connectors: {', '.join(set(e['connector'] for e in spontaneous))}"],
                "Check for faulty cables or monitor sleep bugs."
            ))

        if unknown_context:
            issues.append(create_issue(
                "graphics",
                "Connector warning, context unknown",
                "Warning",
                [f"Unique incidents: {len(unknown_context)}", f"Connectors: {', '.join(set(e['connector'] for e in unknown_context))}"],
                "Ensure this is not just an unplug event."
            ))

    if unique_plasma_timeout:
        issues.append(create_issue(
            "graphics",
            "plasmashell hung during stop-sigterm",
            "Warning",
            [f"Unique incidents: {len(unique_plasma_timeout)}"],
            "Check for blocked IO or IPC within plasmashell during shutdown."
        ))

    if unique_dbus_timeout:
        issues.append(create_issue(
            "graphics",
            "desktop D-Bus timeout",
            "Warning",
            [f"Unique incidents: {len(unique_dbus_timeout)}"],
            "A desktop service (like kded6 or waitforname) timed out on DBus."
        ))

    if explicit_dbus_timeouts:
        issues.append(create_issue(
            "graphics",
            "Targeted PlasmaShell D-Bus probe timed out",
            "Warning",
            [f"Explicit probes: {len(explicit_dbus_timeouts)}"],
            "plasmashell D-Bus targeted probe timed out."
        ))

    return issues
