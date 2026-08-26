#!/usr/bin/env python3
"""Evidence-based freeze classifiers used by reports and host audits."""
from __future__ import annotations

import re
from typing import Any


def _max_sample(samples: list[dict[str, Any]], path: tuple[str, ...], default: float = 0.0) -> float:
    value = default
    for sample in samples:
        current: Any = sample
        for key in path:
            if not isinstance(current, dict):
                current = None
                break
            current = current.get(key)
        try:
            value = max(value, float(current or 0))
        except (TypeError, ValueError):
            pass
    return value


def _min_sample(samples: list[dict[str, Any]], path: tuple[str, ...], default: float = 1_000_000.0) -> float:
    value = default
    for sample in samples:
        current: Any = sample
        for key in path:
            if not isinstance(current, dict):
                current = None
                break
            current = current.get(key)
        try:
            number = float(current)
            if number:
                value = min(value, number)
        except (TypeError, ValueError):
            pass
    return value


def classify_freeze_evidence(findings: list[dict[str, Any]], canary: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    canary = canary or {}
    samples = canary.get("samples") or []
    all_evidence = "\n".join(
        str(line)
        for finding in findings
        for line in finding.get("evidence", [])
    )
    ids = {finding.get("id") for finding in findings}
    classes: list[dict[str, Any]] = []

    display_score = 0
    display_supports = []
    if re.search(r"i915|drm|atomic update failure|GPU HANG", all_evidence, re.I) or ids & {"intel_display", "other_gpu"}:
        display_score += 3
        display_supports.append("DRM/i915/GPU display errors were recorded.")
    if re.search(r"kwin|wayland|compositor", all_evidence, re.I) or "wayland" in ids:
        display_score += 2
        display_supports.append("KWin/Wayland/compositor evidence was recorded.")
    if any((sample.get("desktop_heartbeat_age_s") or 0) > 20 and sample.get("kwin_ok") is False for sample in samples[-20:]):
        display_score += 2
        display_supports.append("Desktop heartbeat became stale while system telemetry still existed.")
    if display_score:
        classes.append({
            "id": "display_stack_compositor_hang",
            "title": "Display-stack / compositor hang",
            "confidence": "high" if display_score >= 5 else "moderate",
            "supports": display_supports,
            "conflicts": [],
            "missing": ["TTY reachability during the event"] if display_score < 5 else [],
            "next_action": "Keep app GPU acceleration disabled, update stable graphics stack, and run one-monitor Wayland A/B testing.",
        })

    mem_available = _min_sample(samples, ("memory", "mem_available_mb"))
    swap_used = _max_sample(samples, ("memory", "swap_used_mb"))
    swap_total = _max_sample(samples, ("memory", "swap_total_mb"))
    io_full = _max_sample(samples, ("psi_io", "full_avg10"))
    mem_some = _max_sample(samples, ("psi_mem", "some_avg10"))
    load1 = _max_sample(samples, ("load1",))
    memory_score = 0
    memory_supports = []
    if mem_available < 800:
        memory_score += 2
        memory_supports.append(f"MemAvailable fell below 800 MiB ({int(mem_available)} MiB).")
    if swap_total and swap_used / swap_total >= 0.90:
        memory_score += 3
        memory_supports.append(f"Swap/zram exceeded 90% usage ({int(swap_used)}/{int(swap_total)} MiB).")
    if io_full >= 40 or mem_some >= 20:
        memory_score += 3
        memory_supports.append(f"Pressure was high: memory PSI some={mem_some:.1f}, I/O PSI full={io_full:.1f}.")
    if load1 >= 20:
        memory_score += 1
        memory_supports.append(f"Load average exceeded 20 ({load1:.1f}).")
    if "oom" in ids or re.search(r"out of memory|oom-kill|systemd-oomd", all_evidence, re.I):
        memory_score += 2
        memory_supports.append("OOM or systemd-oomd events were recorded.")
    if memory_score:
        classes.append({
            "id": "memory_pressure_desktop_starvation",
            "title": "Memory-pressure desktop starvation",
            "confidence": "high" if memory_score >= 6 else "moderate" if memory_score >= 3 else "low",
            "supports": memory_supports,
            "conflicts": ["Display errors may be concurrent rather than causal."] if display_score else [],
            "missing": ["Per-process/cgroup memory growth immediately before freeze"] if not samples else [],
            "next_action": "Preserve rolling telemetry and identify memory-growing cgroups before swap/zram reaches saturation.",
        })

    if re.search(r"plasmashell", all_evidence, re.I) and not re.search(r"kwin|wayland|i915|drm|GPU HANG", all_evidence, re.I):
        classes.append({
            "id": "plasma_shell_only_failure",
            "title": "Plasma shell / panel-only failure",
            "confidence": "moderate",
            "supports": ["Plasma shell evidence appears without matching KWin/DRM/system failure evidence."],
            "conflicts": [],
            "missing": ["KWin responsiveness and app-window responsiveness during the event"],
            "next_action": "Try plasmashell --replace before rebooting the whole machine.",
        })

    if re.search(r"kernel panic|watchdog|hard lockup|pstore|kdump", all_evidence, re.I) or ids & {"kernel_panic", "watchdog"}:
        classes.append({
            "id": "whole_system_kernel_failure",
            "title": "Whole-system / kernel-level failure",
            "confidence": "high",
            "supports": ["Kernel panic/watchdog/pstore/kdump evidence was recorded."],
            "conflicts": [],
            "missing": [],
            "next_action": "Preserve kdump/pstore evidence and avoid display-only conclusions.",
        })

    if re.search(r"usb|uas|I/O error|Buffer I/O|EXT4|JBD2", all_evidence, re.I):
        classes.append({
            "id": "external_storage_disconnect_or_io_failure",
            "title": "External storage disconnect or I/O failure",
            "confidence": "moderate",
            "supports": ["USB/storage I/O evidence was recorded."],
            "conflicts": [],
            "missing": ["Stable device attribution from lsblk/udevadm/sysfs"],
            "next_action": "Attribute the failing /dev node to physical media before blaming the internal system disk.",
        })

    if re.search(r"AER|PCIe Bus Error|rtw88_8821ce|RTL8821CE", all_evidence, re.I):
        classes.append({
            "id": "correctable_pcie_aer_observed",
            "title": "Correctable PCIe/AER errors observed",
            "confidence": "low",
            "supports": ["Correctable PCIe/AER messages were present."],
            "conflicts": ["Correctable AER is often non-fatal without freeze-time correlation."],
            "missing": ["Temporal correlation with an actual freeze boundary"],
            "next_action": "Monitor and correlate; do not suppress AER globally just to quiet logs.",
        })

    return classes
