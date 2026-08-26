#!/usr/bin/env python3
"""Conservative early-warning decisions for freeze prevention.

This module only decides what to warn about. It deliberately performs no process
termination, reboot, compositor restart, or privileged mutation.
"""
from __future__ import annotations

from typing import Any


def evaluate_sample(sample: dict[str, Any]) -> dict[str, Any]:
    memory = sample.get("memory") or {}
    psi_mem = sample.get("psi_mem") or {}
    psi_io = sample.get("psi_io") or {}
    processes = sample.get("processes") or {}
    mem_available = float(memory.get("mem_available_mb") or sample.get("mem_available_mb") or 0)
    mem_total = float(memory.get("mem_total_mb") or sample.get("mem_total_mb") or 0)
    swap_used = float(memory.get("swap_used_mb") or sample.get("swap_used_mb") or 0)
    swap_total = float(memory.get("swap_total_mb") or sample.get("swap_total_mb") or 0)
    mem_some = float(psi_mem.get("some_avg10") or sample.get("psi_memory_some_avg10") or 0)
    io_full = float(psi_io.get("full_avg10") or sample.get("psi_io_full_avg10") or 0)
    load1 = float(sample.get("load1") or 0)

    reasons = []
    severity = "ok"
    if mem_total and mem_available / mem_total < 0.08:
        reasons.append(f"MemAvailable is below 8% ({int(mem_available)} MiB available).")
    if swap_total and swap_used / swap_total > 0.85:
        reasons.append(f"Swap/zram usage is above 85% ({int(swap_used)}/{int(swap_total)} MiB).")
    if mem_some >= 20:
        reasons.append(f"Memory PSI some avg10 is high ({mem_some:.1f}%).")
    if io_full >= 30:
        reasons.append(f"I/O PSI full avg10 is high ({io_full:.1f}%).")
    if load1 >= 20:
        reasons.append(f"Load average is very high ({load1:.1f}).")
    if reasons:
        severity = "critical" if len(reasons) >= 2 or io_full >= 50 else "warning"

    offenders = []
    for proc in processes.get("top_rss") or []:
        offenders.append({
            "pid": proc.get("pid"),
            "name": proc.get("name"),
            "group": proc.get("group"),
            "rss_mb": int((proc.get("rss_kb") or 0) / 1024),
            "swap_mb": int((proc.get("swap_kb") or 0) / 1024),
        })
    offenders = offenders[:8]

    actions = []
    if severity != "ok":
        actions.extend([
            "Preserve an immediate telemetry snapshot.",
            "Notify the desktop user about impending memory/I/O starvation.",
            "Review top memory consumers before terminating anything.",
        ])
        if offenders:
            actions.append("Offer user-confirmed termination for a clearly identified offender; do not kill automatically.")

    plasma_action = None
    if sample.get("plasmashell_ok") is False and sample.get("kwin_ok") is True:
        plasma_action = "Offer plasmashell --replace as a panel-only recovery action."

    return {
        "severity": severity,
        "reasons": reasons,
        "likely_offenders": offenders,
        "recommended_actions": actions,
        "plasma_shell_recovery": plasma_action,
        "automatic_action_taken": False,
    }
