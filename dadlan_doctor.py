from typing import Any

def analyze_dadlan(failed_units: list[str]) -> list[dict[str, Any]]:
    dadlan_failed = [u for u in failed_units if "mnt-dadlan" in u]
    
    issues = []
    
    def create_issue(category, title, status, evidence, action):
        return {
            "category": category,
            "title": title,
            "status": status,
            "evidence": evidence,
            "recommended_action": action,
        }
        
    if dadlan_failed:
        issues.append(create_issue(
            "network",
            "Multiple optional remote mounts currently failed because hosts are unavailable.",
            "Configuration / Operational",
            [f"{len(dadlan_failed)} DadLAN mount units are in failed state.",
             "This is an expected/operational network mount failure, not a machine-health failure."],
            "Update /etc/fstab to prevent offline laptops from creating permanent failed units (e.g., adding noauto, x-systemd.idle-timeout=1min, x-systemd.mount-timeout=10s)."
        ))
        
    return issues
