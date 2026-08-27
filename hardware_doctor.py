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

def generate_event_id(dt: datetime, normalized_msg: str) -> str:
    base = f"{dt.replace(microsecond=0).isoformat()}_{normalized_msg}"
    return hashlib.md5(base.encode()).hexdigest()

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

def analyze_hardware_events(lines: list[str]) -> list[dict[str, Any]]:
    raw_pcie = []
    raw_usb = []
    raw_sda = []
    
    unique_pcie = {}
    unique_usb = {}
    unique_sda = {}
    
    for line in lines:
        dt = extract_timestamp(line)
        if not dt: continue
            
        if "rtw88_8821ce" in line and "PCIe Bus Error" in line:
            raw_pcie.append(line)
            norm = re.sub(r"AVANCE-WS7.*?kernel: ", "", line).strip()
            eid = generate_event_id(dt, norm)
            if eid not in unique_pcie:
                unique_pcie[eid] = {"time": dt, "raw": line, "norm": norm}
                
        elif "usb usb1-port14:" in line and "unable to enumerate USB device" in line:
            raw_usb.append(line)
            norm = "usb usb1-port14 unable to enumerate"
            eid = generate_event_id(dt, norm)
            if eid not in unique_usb:
                unique_usb[eid] = {"time": dt, "raw": line, "norm": norm}
                
        elif "sda" in line and ("Buffer I/O error" in line or "device offline" in line or "EXT4-fs" in line):
            raw_sda.append(line)
            norm = re.sub(r"AVANCE-WS7.*?kernel: ", "", line).strip()
            eid = generate_event_id(dt, norm)
            if eid not in unique_sda:
                unique_sda[eid] = {"time": dt, "raw": line, "norm": norm}

    issues = []
    def create_issue(category, title, status, evidence, action):
        return {
            "category": category,
            "title": title,
            "status": status,
            "evidence": evidence,
            "recommended_action": action,
        }
        
    if unique_pcie:
        pcie_list = sorted(unique_pcie.values(), key=lambda x: x["time"])
        clusters = cluster_events(pcie_list)
        issues.append(create_issue(
            "hardware",
            "Persistent corrected PCIe errors from Realtek Wi-Fi adapter — monitoring recommended.",
            "Monitoring",
            [
                f"Incident clusters: {len(clusters)}",
                f"Unique events: {len(pcie_list)}",
                f"Raw evidence appearances: {len(raw_pcie)}",
                "Errors include Bad DLLP and Replay Timer Timeout.",
                f"First seen: {pcie_list[0]['time']}",
                f"Last seen: {pcie_list[-1]['time']}"
            ],
            "Do not disable AER or ASPM. Monitor for correlation with Wi-Fi dropouts."
        ))
        
    if unique_usb:
        usb_list = sorted(unique_usb.values(), key=lambda x: x["time"])
        clusters = cluster_events(usb_list)
        issues.append(create_issue(
            "hardware",
            "USB port 1-14 (Realtek Bluetooth 4.2 Adapter) repeatedly fails enumeration.",
            "Investigate",
            [
                f"Incident clusters: {len(clusters)}",
                f"Unique events: {len(usb_list)}",
                f"Raw evidence appearances: {len(raw_usb)}",
                f"First seen: {usb_list[0]['time']}",
                f"Last seen: {usb_list[-1]['time']}"
            ],
            "Identify internal connectivity issues for the Bluetooth combo module."
        ))
        
    if unique_sda:
        sda_list = sorted(unique_sda.values(), key=lambda x: x["time"])
        clusters = cluster_events(sda_list, window_seconds=120)
        issues.append(create_issue(
            "storage",
            "Historical external/removable storage I/O failure.",
            "Historical",
            [
                f"Incident clusters: {len(clusters)}",
                f"Unique events: {len(sda_list)}",
                f"Raw evidence appearances: {len(raw_sda)}",
                "Errors include Buffer I/O errors and device offline events.",
                "This does NOT attribute to the internal NVMe boot drive.",
                f"First seen: {sda_list[0]['time']}",
                f"Last seen: {sda_list[-1]['time']}"
            ],
            "Confirm if a failing USB drive or external enclosure was attached around these dates."
        ))
        
    return issues
