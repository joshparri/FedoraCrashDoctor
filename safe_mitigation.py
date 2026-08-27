#!/usr/bin/env python3
"""Conservative early-warning decisions for freeze prevention.

This module only decides what to warn about. It deliberately performs no process
termination, reboot, compositor restart, or privileged mutation.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

def evaluate_sample(sample: dict[str, Any]) -> dict[str, Any]:
    memory = sample.get("memory") or {}
    psi_mem = sample.get("psi_mem") or {}
    psi_io = sample.get("psi_io") or {}
    
    mem_available = float(memory.get("mem_available_mb") or sample.get("mem_available_mb") or 0)
    mem_total = float(memory.get("mem_total_mb") or sample.get("mem_total_mb") or 0)
    swap_used = float(memory.get("swap_used_mb") or sample.get("swap_used_mb") or 0)
    swap_total = float(memory.get("swap_total_mb") or sample.get("swap_total_mb") or 0)
    mem_some = float(psi_mem.get("some_avg10") or sample.get("psi_memory_some_avg10") or 0)
    io_full = float(psi_io.get("full_avg10") or sample.get("psi_io_full_avg10") or 0)
    
    mem_avail_pct = (mem_available / mem_total) if mem_total else 1.0
    swap_used_pct = (swap_used / swap_total) if swap_total else 0.0
    
    hb_age = sample.get("desktop_heartbeat_age_s")
    kwin_ok = sample.get("kwin_ok")
    plasma_ok = sample.get("plasmashell_ok")

    severity = "ok"
    category = "healthy"
    title = "System healthy"
    reasons = []

    if mem_avail_pct < 0.08 and swap_used_pct > 0.85 and mem_some >= 20 and io_full >= 20:
        severity = "critical"
        category = "memory"
        title = f"Memory pressure is critical \u2014 swap is {int(swap_used_pct * 100)}% full."
        reasons = [
            f"Available RAM: {int(mem_available)} MB",
            f"zram/swap: {int(swap_used_pct * 100)}%",
            "Memory pressure: severe",
            "I/O pressure: severe"
        ]
    elif mem_avail_pct < 0.15 and swap_used_pct > 0.70 and mem_some >= 10:
        severity = "warning"
        category = "memory"
        title = "Memory pressure is rising"
        reasons = [
            f"Available RAM: {int(mem_available)} MB",
            f"zram/swap: {int(swap_used_pct * 100)}%",
            "Memory pressure: elevated"
        ]
    elif hb_age is not None and hb_age > 20:
        severity = "warning"
        category = "desktop"
        title = "Desktop heartbeat lost"
        reasons = [f"Desktop heartbeat stale ({hb_age}s)"]
    elif kwin_ok is False:
        severity = "warning"
        category = "desktop"
        title = "KWin Wayland unresponsive"
        reasons = ["KWin failed its ping response."]
    elif plasma_ok is False and kwin_ok is True:
        severity = "warning"
        category = "desktop"
        title = "Plasmashell missing"
        reasons = ["plasmashell is not running, but KWin is OK."]
    elif mem_avail_pct < 0.08 and swap_used_pct > 0.85:
        # Fallback to critical if missing PSI data but RAM is completely exhausted
        severity = "critical"
        category = "memory"
        title = f"Memory pressure is critical \u2014 swap is {int(swap_used_pct * 100)}% full."
        reasons = [
            f"Available RAM: {int(mem_available)} MB",
            f"zram/swap: {int(swap_used_pct * 100)}%"
        ]
    elif mem_avail_pct < 0.15 and swap_used_pct > 0.70:
        severity = "warning"
        category = "memory"
        title = "Memory pressure is rising"
        reasons = [
            f"Available RAM: {int(mem_available)} MB",
            f"zram/swap: {int(swap_used_pct * 100)}%"
        ]

    offenders = []
    processes = sample.get("processes") or {}
    for proc in (processes.get("top_rss") or [])[:3]:
        name = proc.get("name")
        group = proc.get("group") or name
        rss_mb = int((proc.get("rss_kb") or 0) / 1024)
        if rss_mb > 500:
            offenders.append(f"{group} \u2014 {rss_mb} MB")

    actions = []
    if severity == "warning" and category == "memory":
        actions.append("The desktop is still responsive.")
        actions.append("Closing an unneeded heavy application now may prevent a freeze.")
    elif severity == "critical" and category == "memory":
        actions.append("Save important work or close heavy background applications.")
    
    plasma_recovery = None
    if plasma_ok is False and kwin_ok is True:
        plasma_recovery = "Offer plasmashell --replace as a panel-only recovery action."

    return {
        "severity": severity,
        "category": category,
        "title": title,
        "reasons": reasons,
        "likely_offenders": offenders,
        "recommended_actions": actions,
        "timestamp": sample.get("ts", ""),
        "plasma_shell_recovery": plasma_recovery,
        "automatic_action_taken": False
    }


class StabilityController:
    def __init__(self, owner_config: Path = Path("/etc/fedora-crash-doctor/owner.json"), out_dir: Path = Path("/run/fedora-crash-doctor")):
        self.state = "ok" # ok, pending, warning, critical, recovering
        self.pressure_count = 0
        self.recovery_count = 0
        self.owner_config = owner_config
        self.out_dir = out_dir
        
    def get_owner(self) -> dict[str, int] | None:
        try:
            if not self.owner_config.exists():
                return None
            data = json.loads(self.owner_config.read_text())
            return {"uid": int(data["uid"]), "gid": int(data["gid"])}
        except Exception:
            return None
        
    def process_sample(self, sample: dict[str, Any]) -> dict[str, Any] | None:
        eval_result = evaluate_sample(sample)
        raw_sev = eval_result["severity"]

        if raw_sev in {"warning", "critical"}:
            self.recovery_count = 0
            self.pressure_count += 1
        else:
            self.pressure_count = 0
            self.recovery_count += 1

        new_state = self.state
        emit = False

        if self.state == "ok":
            if raw_sev in {"warning", "critical"}:
                new_state = "pending"
        elif self.state == "pending":
            if self.pressure_count >= 2:
                new_state = raw_sev
                emit = True
            elif raw_sev == "ok" and self.recovery_count >= 2:
                new_state = "ok"
        elif self.state == "warning":
            if raw_sev == "critical" and self.pressure_count >= 2:
                new_state = "critical"
                emit = True
            elif raw_sev == "ok":
                new_state = "recovering"
                emit = True
        elif self.state == "critical":
            if raw_sev == "ok":
                new_state = "recovering"
                emit = True
        elif self.state == "recovering":
            if raw_sev in {"warning", "critical"}:
                new_state = raw_sev
                emit = True
            elif self.recovery_count >= 5:
                new_state = "ok"
                emit = True

        self.state = new_state

        if emit:
            out = {
                "state": self.state,
                "category": eval_result.get("category", ""),
                "title": eval_result.get("title", ""),
                "reasons": eval_result.get("reasons", []),
                "likely_offenders": eval_result.get("likely_offenders", []),
                "recommended_actions": eval_result.get("recommended_actions", []),
                "timestamp": eval_result.get("timestamp", ""),
                "automatic_action_taken": False
            }
            if self.state in {"recovering", "ok"}:
                out["title"] = "System recovered"
                out["reasons"] = ["Pressure has subsided and conditions are healthy."]
                out["recommended_actions"] = []
                out["category"] = "healthy"
            
            self._notify_user(out)
            return out

        return None
        
    def _notify_user(self, payload: dict[str, Any]) -> None:
        owner = self.get_owner()
        if not owner:
            return
            
        try:
            self.out_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
            
            target = self.out_dir / "stability-event.json"
            fd, name = tempfile.mkstemp(prefix="stability-", dir=self.out_dir)
            with os.fdopen(fd, "w") as stream:
                json.dump(payload, stream)
                stream.flush()
                os.fsync(stream.fileno())
                
            os.chown(name, owner["uid"], owner["gid"])
            os.chmod(name, 0o600)
            os.replace(name, target)
        except Exception:
            pass
