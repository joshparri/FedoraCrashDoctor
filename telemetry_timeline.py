#!/usr/bin/env python3
"""Build correlated events from rolling canary telemetry."""
from __future__ import annotations

from typing import Any


def _number(value: Any) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def build_telemetry_timeline(samples: list[dict[str, Any]]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for sample in samples:
        ts = str(sample.get("ts") or sample.get("epoch") or "")
        memory = sample.get("memory") or {}
        psi_mem = sample.get("psi_mem") or {}
        psi_io = sample.get("psi_io") or {}
        mem_available = _number(memory.get("mem_available_mb") or sample.get("mem_available_mb"))
        swap_used = _number(memory.get("swap_used_mb") or sample.get("swap_used_mb"))
        swap_total = _number(memory.get("swap_total_mb") or sample.get("swap_total_mb"))
        io_full = _number(psi_io.get("full_avg10") or sample.get("psi_io_full_avg10"))
        mem_some = _number(psi_mem.get("some_avg10") or sample.get("psi_memory_some_avg10"))
        load1 = _number(sample.get("load1"))

        candidates = []
        if mem_available and mem_available < 800:
            candidates.append(("low_memory", f"MemAvailable below 800 MiB ({int(mem_available)} MiB)"))
        if swap_total and swap_used / swap_total >= 0.90:
            candidates.append(("swap_saturated", f"Swap/zram above 90% ({int(swap_used)}/{int(swap_total)} MiB)"))
        if io_full >= 40:
            candidates.append(("high_io_psi", f"I/O PSI full avg10 {io_full:.1f}%"))
        if mem_some >= 20:
            candidates.append(("high_memory_psi", f"Memory PSI some avg10 {mem_some:.1f}%"))
        if load1 >= 20:
            candidates.append(("high_load", f"Load average {load1:.1f}"))
        if (sample.get("desktop_heartbeat_age_s") or 0) and _number(sample.get("desktop_heartbeat_age_s")) > 20:
            candidates.append(("desktop_heartbeat_lost", f"Desktop heartbeat age {sample.get('desktop_heartbeat_age_s')}s"))
        if sample.get("kwin_ok") is False:
            candidates.append(("kwin_unresponsive", "KWin heartbeat failed"))
        if sample.get("plasmashell_ok") is False and sample.get("kwin_ok") is True:
            candidates.append(("plasmashell_only", "plasmashell absent/unhealthy while KWin heartbeat succeeded"))

        for event_type, summary in candidates:
            key = (event_type, summary)
            if key in seen:
                continue
            seen.add(key)
            events.append({"timestamp": ts, "source": "canary", "type": event_type, "summary": summary})
    return events
