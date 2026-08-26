#!/usr/bin/env python3
"""Read-only AVANCE-WS7/Fedora host stability audit.

This complements Fedora Crash Doctor's post-crash analysis with live prevention
checks. It does not modify the host, install packages, change kernel parameters,
kill processes, or restart services.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from version import app_version

VERSION = app_version()
SAFE_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C.UTF-8", "LANG": "C.UTF-8"}


def run(argv: list[str], timeout: int = 20) -> dict[str, Any]:
    if not argv or shutil.which(argv[0], path=SAFE_ENV["PATH"]) is None:
        return {"status": "not_available", "returncode": 127, "output": f"Not installed: {argv[0] if argv else ''}"}
    try:
        proc = subprocess.run(
            argv,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            env=SAFE_ENV,
            check=False,
        )
        return {"status": "ok" if proc.returncode == 0 else "error", "returncode": proc.returncode, "output": proc.stdout or ""}
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode(errors="replace")
        return {"status": "timeout", "returncode": 124, "output": output + f"\nTimed out after {timeout} seconds."}


def read(path: str, default: str = "") -> str:
    try:
        return Path(path).read_text(errors="replace").strip()
    except Exception:
        return default


def rpm_versions(names: list[str]) -> dict[str, list[str]]:
    result = run(["rpm", "-q", *names], 20)
    versions: dict[str, list[str]] = {name: [] for name in names}
    for line in result["output"].splitlines():
        if line.startswith("package ") or not line:
            continue
        for name in names:
            if line.startswith(name + "-"):
                versions[name].append(line)
    return versions


def service_state(name: str) -> dict[str, str]:
    active = run(["systemctl", "is-active", name], 10)["output"].strip() or "unknown"
    enabled = run(["systemctl", "is-enabled", name], 10)["output"].strip() or "unknown"
    return {"active": active, "enabled": enabled}


def parse_swapon(text: str) -> list[dict[str, str]]:
    rows = []
    for line in text.splitlines()[1:]:
        bits = line.split()
        if len(bits) >= 5:
            rows.append({"name": bits[0], "type": bits[1], "size": bits[2], "used": bits[3], "priority": bits[4]})
    return rows


def issue(category: str, title: str, status: str, evidence: list[str], action: str) -> dict[str, Any]:
    return {
        "category": category,
        "title": title,
        "status": status,
        "evidence": evidence,
        "recommended_action": action,
    }


def audit() -> dict[str, Any]:
    uname = run(["uname", "-r"], 10)["output"].strip()
    packages = rpm_versions([
        "kernel-core",
        "mesa-dri-drivers",
        "plasma-workspace",
        "kwin-wayland",
        "systemd-oomd-defaults",
        "zram-generator-defaults",
        "kexec-tools",
    ])
    check_updates = run(["dnf", "check-update", "--refresh", "kernel-core", "mesa-dri-drivers", "plasma-workspace"], 90)
    oomd = service_state("systemd-oomd.service")
    canary = service_state("fedora-crash-doctor-canary.service")
    autoscan = service_state("fedora-crash-doctor-autoscan.service")
    kdump = service_state("kdump.service")
    swapon = run(["swapon", "--show", "--bytes"], 10)
    zramctl = run(["zramctl", "--output-all", "--bytes"], 10)
    free = run(["free", "-h"], 10)
    psi_memory = read("/proc/pressure/memory")
    psi_io = read("/proc/pressure/io")
    cmdline = read("/proc/cmdline")
    kexec_loaded = read("/sys/kernel/kexec_crash_loaded", "unknown")
    session = run(["loginctl", "show-session", os.environ.get("XDG_SESSION_ID", ""), "-p", "Type", "-p", "Desktop", "-p", "State"], 10)
    displays = run(["kscreen-doctor", "-o"], 10)
    kernel_tail = run(["journalctl", "-k", "-b", "--no-pager"], 20)

    interesting = []
    for line in kernel_tail["output"].splitlines():
        if re.search(r"i915|drm|atomic update failure|GPU HANG|kwin|oom|out of memory|usb|uas|I/O error|EXT4|JBD2|btrfs|aer|pcie", line, re.I):
            interesting.append(line)
    interesting = interesting[-120:]

    issues: list[dict[str, Any]] = []
    if re.search(r"kernel-core\.\S+\s+\S+\s+updates", check_updates["output"]):
        issues.append(issue(
            "updates",
            "Stable Fedora kernel update is available",
            "high-confidence preventative fix",
            [f"Running kernel: {uname}", *check_updates["output"].splitlines()[:8]],
            "Run sudo dnf upgrade --refresh from stable repositories, then reboot into the newest kernel.",
        ))

    if oomd["active"] == "active" and oomd["enabled"] == "enabled":
        issues.append(issue(
            "memory",
            "systemd-oomd is active",
            "confirmed protection",
            [f"systemd-oomd active={oomd['active']} enabled={oomd['enabled']}", "Fedora uses PSI/cgroup-aware oomd policy by default."],
            "Keep systemd-oomd enabled. Do not install a competing OOM daemon unless later evidence proves oomd cannot act soon enough.",
        ))
    else:
        issues.append(issue(
            "memory",
            "systemd-oomd is not fully active",
            "confirmed problem",
            [f"systemd-oomd active={oomd['active']} enabled={oomd['enabled']}"],
            "Enable the Fedora default oomd policy after reviewing logs: sudo systemctl enable --now systemd-oomd.service.",
        ))

    zram_rows = parse_swapon(swapon["output"])
    if any(row["name"].startswith("/dev/zram") for row in zram_rows):
        issues.append(issue(
            "memory",
            "zram swap is present",
            "confirmed protection",
            [swapon["output"].strip(), zramctl["output"].strip()],
            "Monitor pressure and process growth before changing zram size. Current priority/usage should be captured after any future freeze.",
        ))
    else:
        issues.append(issue(
            "memory",
            "zram swap was not detected",
            "confirmed problem",
            [swapon["output"].strip() or "swapon reported no swap devices"],
            "Inspect zram-generator-defaults and restore Fedora's zram setup before adding conventional swap.",
        ))

    atomic_lines = [line for line in interesting if re.search(r"i915.*Atomic update failure|atomic update failure", line, re.I)]
    if atomic_lines:
        issues.append(issue(
            "graphics",
            "Current boot has Intel i915 atomic update failures",
            "confirmed problem",
            atomic_lines[-8:],
            "Keep Chrome/VS Code GPU acceleration disabled, update kernel/Mesa/Plasma from stable repos, and run a one-monitor Wayland A/B test.",
        ))

    display_count = len(re.findall(r"Output:\s+\d+ .*?\n\s+enabled\n\s+connected", displays["output"]))
    if display_count >= 2:
        issues.append(issue(
            "graphics",
            "Multi-monitor Wayland topology is active",
            "experiment/A-B test",
            [f"Connected enabled display count: {display_count}"],
            "Test Wayland with one monitor for a meaningful period. If freezes stop, keep multi-monitor/i915 as the leading cause.",
        ))

    pcie_lines = [line for line in interesting if re.search(r"AER|PCIe Bus Error|rtw88_8821ce|RTL8821CE", line, re.I)]
    if pcie_lines:
        issues.append(issue(
            "pcie",
            "Correctable PCIe/AER messages observed",
            "monitoring only",
            pcie_lines[-8:],
            "Keep correlating timestamps. Do not add pci=noaer or disable ASPM unless uncorrectable errors or freeze-time correlation appears.",
        ))

    usb_lines = [line for line in interesting if re.search(r"usb|uas|I/O error|EXT4|JBD2", line, re.I)]
    if usb_lines:
        issues.append(issue(
            "storage",
            "USB/storage messages exist in the kernel log",
            "monitoring only",
            usb_lines[-8:],
            "Attribute errors to physical devices by VID:PID/path before blaming the internal NVMe. Replace/test cables/enclosures for recurring external-drive errors.",
        ))

    if canary["active"] == "active" and kdump["active"] == "active" and kexec_loaded == "1" and Path("/var/log/journal").exists():
        issues.append(issue(
            "capture",
            "Crash capture infrastructure is active",
            "confirmed protection",
            [
                f"canary active={canary['active']} enabled={canary['enabled']}",
                f"autoscan active={autoscan['active']} enabled={autoscan['enabled']}",
                f"kdump active={kdump['active']} enabled={kdump['enabled']}",
                f"kexec_crash_loaded={kexec_loaded}",
                "persistent journal directory exists",
            ],
            "Keep these enabled. After any freeze, prefer TTY recovery and run Crash Doctor before making unrelated changes.",
        ))
    else:
        issues.append(issue(
            "capture",
            "Crash capture infrastructure is incomplete",
            "confirmed problem",
            [
                f"canary active={canary['active']} enabled={canary['enabled']}",
                f"autoscan active={autoscan['active']} enabled={autoscan['enabled']}",
                f"kdump active={kdump['active']} enabled={kdump['enabled']}",
                f"kexec_crash_loaded={kexec_loaded}",
                f"persistent journal={Path('/var/log/journal').exists()}",
            ],
            "Repair capture setup with Fedora Crash Doctor before relying on the next post-crash report.",
        ))

    unsupported = [
        "Internal NVMe failure is not the leading explanation unless SMART/NVMe/Btrfs errors correlate with freezes.",
        "General Fedora/RPM corruption is not supported by the current health checks.",
        "Realtek Wi-Fi/PCIe correctable errors should not be treated as causal without timing correlation.",
        "Global UAS/ASPM/i915 kernel parameters should not be added speculatively.",
    ]

    return {
        "schema": 1,
        "generated": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "host": {
            "hostname": run(["hostname"], 10)["output"].strip(),
            "kernel": uname,
            "cmdline_relevant": " ".join(x for x in cmdline.split() if x.startswith(("i915.", "crashkernel="))),
            "session": session["output"].strip(),
        },
        "packages": packages,
        "memory": {"free": free["output"], "swapon": swapon["output"], "zramctl": zramctl["output"], "psi_memory": psi_memory, "psi_io": psi_io},
        "display": {"kscreen": displays["output"]},
        "issues": issues,
        "not_supported_by_current_evidence": unsupported,
        "sources_checked": {
            "fedora_stable_updates": check_updates["status"],
            "kernel_log": kernel_tail["status"],
            "systemd_oomd": oomd,
            "canary": canary,
            "autoscan": autoscan,
            "kdump": kdump,
        },
    }


def render_markdown(data: dict[str, Any]) -> str:
    lines = [
        "# Fedora Crash Doctor Host Stability Audit",
        "",
        f"Generated: {data['generated']}",
        "",
        "## Host",
        "",
        f"- Hostname: `{data['host']['hostname']}`",
        f"- Kernel: `{data['host']['kernel']}`",
        f"- Relevant kernel args: `{data['host']['cmdline_relevant'] or 'none'}`",
        "",
        "## Findings",
        "",
    ]
    for item in data["issues"]:
        lines.extend([
            f"### {item['title']}",
            "",
            f"- Category: `{item['category']}`",
            f"- Classification: `{item['status']}`",
            "- Evidence:",
        ])
        for evidence in item["evidence"][:12]:
            lines.append(f"  - `{evidence}`")
        lines.extend(["- Recommended action:", f"  - {item['recommended_action']}", ""])
    lines.extend(["## Not Supported By Current Evidence", ""])
    for item in data["not_supported_by_current_evidence"]:
        lines.append(f"- {item}")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a read-only Fedora host stability audit.")
    parser.add_argument("--json", action="store_true", help="write JSON instead of Markdown")
    parser.add_argument("--output", help="write the audit to a file instead of stdout")
    args = parser.parse_args(argv)
    data = audit()
    text = json.dumps(data, indent=2, ensure_ascii=False) if args.json else render_markdown(data)
    if args.output:
        Path(args.output).write_text(text)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
