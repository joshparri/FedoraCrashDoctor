#!/usr/bin/env python3
"""Read-only Fedora crash and reliability evidence collector.

This module is imported by the locked-down privileged broker and the boot-time
autoscan service. It never installs packages, changes configuration, runs
stress tests, repairs filesystems, or writes into user-controlled paths.
"""
from __future__ import annotations

import glob
import ctypes
import json
import os
import platform
import re
import shlex
import shutil
import socket
import signal
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

MAX_OUTPUT = 700_000
DEFAULT_TIMEOUT = 40
Progress = Callable[[int, int, str], None]


def _child_parent_death_signal() -> None:
    """Ask the kernel to terminate a diagnostic child if its broker dies."""
    try:
        ctypes.CDLL(None).prctl(1, signal.SIGTERM)
    except Exception:
        pass


def _safe_env() -> dict[str, str]:
    return {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LC_ALL": "C.UTF-8",
        "LANG": "C.UTF-8",
        "HOME": "/root",
    }


def run(command: list[str] | str, timeout: int = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """Run a fixed diagnostic command and return bounded combined output."""
    shell = isinstance(command, str)
    display = command if shell else shlex.join(command)
    if not shell and shutil.which(command[0], path=_safe_env()["PATH"]) is None:
        return {
            "command": display,
            "status": "not_available",
            "returncode": 127,
            "duration_seconds": 0,
            "output": f"Command is not installed: {command[0]}",
        }
    started = time.monotonic()
    try:
        proc = subprocess.run(
            command,
            shell=shell,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            env=_safe_env(),
            preexec_fn=_child_parent_death_signal,
        )
        output = proc.stdout or ""
        if len(output) > MAX_OUTPUT:
            output = output[:MAX_OUTPUT] + "\n\n[Output truncated by Fedora Crash Doctor]\n"
        status = "ok" if proc.returncode == 0 else "error"
        # fwupdmgr deliberately returns non-zero for common non-fault states.
        if isinstance(command, list) and command[:2] == ["fwupdmgr", "get-updates"]:
            if re.search(r"No updates available|No updatable devices|Devices with no available firmware updates", output, re.I):
                status = "ok"
        return {
            "command": display,
            "status": status,
            "returncode": proc.returncode,
            "duration_seconds": round(time.monotonic() - started, 2),
            "output": output,
        }
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode(errors="replace")
        return {
            "command": display,
            "status": "timeout",
            "returncode": 124,
            "duration_seconds": round(time.monotonic() - started, 2),
            "output": output + f"\nTimed out after {timeout} seconds.",
        }
    except Exception as exc:  # defensive: diagnostics should continue
        return {
            "command": display,
            "status": "error",
            "returncode": 1,
            "duration_seconds": round(time.monotonic() - started, 2),
            "output": f"{type(exc).__name__}: {exc}",
        }


def read_file(path: str, limit: int = 300_000) -> str:
    try:
        return Path(path).read_text(errors="replace")[:limit]
    except Exception as exc:
        return f"Unable to read {path}: {exc}"


@dataclass
class Task:
    key: str
    title: str
    command: list[str] | str
    timeout: int = DEFAULT_TIMEOUT
    category: str = "Software"


class CheckRunner:
    def __init__(self, tasks: list[Task], progress: Progress | None):
        self.tasks = tasks
        self.progress = progress
        self.checks: dict[str, Any] = {}

    def execute(self) -> dict[str, Any]:
        total = len(self.tasks)
        for index, task in enumerate(self.tasks, start=1):
            if self.progress:
                self.progress(index - 1, total, task.title)
            result = run(task.command, task.timeout)
            result["title"] = task.title
            result["category"] = task.category
            self.checks[task.key] = result
        if self.progress:
            self.progress(total, total, "Analysing and correlating evidence")
        return self.checks


def discover_smart_devices() -> list[str]:
    result = run(["smartctl", "--scan-open"])
    devices = []
    for line in result.get("output", "").splitlines():
        if line.startswith("/dev/"):
            candidate = line.split()[0]
            if re.fullmatch(r"/dev/(?:sd[a-z]+|nvme\d+n\d+|mmcblk\d+)", candidate):
                devices.append(candidate)
    return sorted(set(devices))


def discover_nvme_devices() -> list[str]:
    return sorted(
        path for path in glob.glob("/dev/nvme*n1")
        if re.fullmatch(r"/dev/nvme\d+n\d+", path)
    )


def parse_lspci_inventory(text: str) -> dict[str, dict[str, str]]:
    """Map a PCI address to its description and active kernel driver."""
    inventory: dict[str, dict[str, str]] = {}
    current: str | None = None
    for line in text.splitlines():
        match = re.match(r"^((?:[0-9a-fA-F]{4}:)?[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7])\s+(.+)$", line)
        if match:
            current = canonical_pci(match.group(1))
            inventory[current] = {"description": match.group(2).strip(), "driver": "unknown"}
            continue
        if current:
            driver = re.search(r"Kernel driver in use:\s*(.+)", line)
            if driver:
                inventory[current]["driver"] = driver.group(1).strip()
    return inventory


def canonical_pci(address: str) -> str:
    value = address.lower()
    return value if value.count(":") == 2 else f"0000:{value}"


def extract_pcie_devices(text: str, inventory: dict[str, dict[str, str]]) -> dict[str, dict[str, Any]]:
    """Extract a PCI address anywhere in an AER line and join it to lspci."""
    hits: dict[str, dict[str, Any]] = {}
    address_rx = re.compile(r"\b((?:[0-9a-fA-F]{4}:)?[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7])\b")
    error_rx = re.compile(r"PCIe Bus Error|AER:.*(?:error|Corrected)|BadDLLP|Receiver Error", re.I)
    for line in text.splitlines():
        if not error_rx.search(line):
            continue
        match = address_rx.search(line)
        if not match:
            continue
        address = canonical_pci(match.group(1))
        item = hits.setdefault(address, {
            "count": 0,
            "description": inventory.get(address, {}).get("description", "Unknown PCIe device"),
            "driver": inventory.get(address, {}).get("driver", "unknown"),
            "lines": [],
        })
        item["count"] += 1
        if len(item["lines"]) < 12:
            item["lines"].append(line.strip())
    return hits


def load_baseline(path: str | None) -> dict[str, Any]:
    if not path:
        return {}
    try:
        data = json.loads(Path(path).read_text())
    except Exception:
        return {}
    return {
        item.get("id", item.get("title", "")): {
            "first_seen": item.get("first_seen") or data.get("metadata", {}).get("generated"),
        }
        for item in data.get("findings", [])
    }


def _metadata() -> dict[str, Any]:
    os_release: dict[str, str] = {}
    for line in read_file("/etc/os-release").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            os_release[key] = value.strip('"')
    return {
        "generated": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "hostname": socket.gethostname(),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "fedora": os_release.get("PRETTY_NAME", "Unknown Linux"),
        "boot_id": read_file("/proc/sys/kernel/random/boot_id", 100).strip(),
        "version": "3.0.0",
    }


def build_tasks(mode: str) -> list[Task]:
    tasks = [
        Task("boot_history", "Boot and crash history", ["last", "-x"], 15, "Software"),
        Task("journal_boots", "Available journal boots", ["journalctl", "--list-boots", "--no-pager"], 15, "Software"),
        Task("previous_errors", "Previous boot warnings and errors", ["journalctl", "-b", "-1", "-p", "warning..alert", "--no-pager", "-o", "short-iso-precise"], 50, "Software"),
        Task("previous_kernel_tail", "Final kernel messages from previous boot", "journalctl -b -1 -k --no-pager -o short-iso-precise | tail -1000", 50, "Software"),
        Task("previous_boot_tail", "Final messages from previous boot", "journalctl -b -1 --no-pager -o short-iso-precise | tail -1800", 70, "Software"),
        Task("current_kernel_errors", "Current boot kernel warnings and errors", ["journalctl", "-b", "0", "-k", "-p", "warning..alert", "--no-pager", "-o", "short-iso-precise"], 50, "Software"),
        Task("failed_units", "Failed system services", ["systemctl", "--failed", "--no-pager", "--plain"], 20, "Software"),
        Task("coredumps", "Application core dumps", ["coredumpctl", "list", "--since", "30 days ago", "--no-pager"], 35, "Software"),
        Task("inxi", "System and driver inventory", ["inxi", "-Fxxxz", "--no-host"], 45, "Software"),
        Task("pci", "PCI hardware and active drivers", ["lspci", "-Dnnk"], 25, "PCIe / Network"),
        Task("usb", "USB device tree", ["lsusb", "-tv"], 20, "PCIe / Network"),
        Task("block", "Storage layout", ["lsblk", "-e7", "-o", "NAME,PATH,TYPE,SIZE,FSTYPE,FSVER,MOUNTPOINTS,MODEL,SERIAL,ROTA,TRAN"], 20, "Storage"),
        Task("memory", "Memory, swap and pressure", "free -h; echo; for f in /proc/pressure/cpu /proc/pressure/memory /proc/pressure/io; do echo ===$f===; cat $f; done", 15, "Memory"),
        Task("filesystems", "Filesystem space", ["df", "-hT", "-x", "tmpfs", "-x", "devtmpfs"], 20, "Storage"),
        Task("sensors", "Temperatures and sensors", ["sensors"], 25, "Thermals"),
        Task("firmware_devices", "Firmware-supported devices", ["fwupdmgr", "get-devices"], 50, "Firmware"),
        Task("firmware_updates", "Available firmware updates", ["fwupdmgr", "get-updates"], 50, "Firmware"),
        Task("kernel_cmdline", "Kernel command line", ["cat", "/proc/cmdline"], 10, "Software"),
        Task("kernel_taint", "Kernel taint state", ["cat", "/proc/sys/kernel/tainted"], 10, "Software"),
        Task("modules", "Loaded kernel modules", ["lsmod"], 20, "Software"),
        Task("display_previous", "Graphics/display errors in the previous boot", "journalctl -b -1 --no-pager -o short-iso-precise | grep -iE 'i915|xe |amdgpu|nouveau|nvidia|drm|gpu hang|gpu reset|atomic update failure|framebuffer|flip_done|fence timeout|context provider|kwin' | tail -1800", 60, "Graphics"),
        Task("display_history", "Graphics/display errors across 14 days", "journalctl --since '14 days ago' -k --no-pager -o short-iso-precise | grep -iE 'i915|xe |amdgpu|nouveau|nvidia|drm|gpu hang|gpu reset|atomic update failure|framebuffer|flip_done|fence timeout' | tail -2200", 70, "Graphics"),
        Task("hardware_errors_previous", "Hardware and PCIe errors in the previous boot", "journalctl -b -1 -k --no-pager -o short-iso-precise | grep -iE 'hardware error|machine check|mce:|edac|aer:|pcie bus error|correctable|uncorrectable|bad dllp|poison' | tail -1500", 55, "PCIe / Network"),
        Task("hardware_errors_history", "Hardware and PCIe errors across 30 days", "journalctl --since '30 days ago' -k --no-pager -o short-iso-precise | grep -iE 'hardware error|machine check|mce:|edac|aer:|pcie bus error|correctable|uncorrectable|bad dllp|poison' | tail -2200", 70, "PCIe / Network"),
        Task("rasdaemon_status", "RAS daemon status", ["systemctl", "status", "rasdaemon.service", "--no-pager"], 20, "Memory"),
        Task("oom_previous", "Memory exhaustion in the previous boot", "journalctl -b -1 --no-pager -o short-iso-precise | grep -iE 'out of memory|oom-kill|killed process|systemd-oomd.*killed' | tail -800", 50, "Memory"),
        Task("oom_history", "Memory exhaustion across 30 days", "journalctl --since '30 days ago' --no-pager -o short-iso-precise | grep -iE 'out of memory|oom-kill|killed process|systemd-oomd.*killed' | tail -1200", 60, "Memory"),
        Task("thermal_previous", "Thermal events in the previous boot", "journalctl -b -1 -k --no-pager -o short-iso-precise | grep -iE 'thermal|overheat|critical temperature|throttl' | tail -800", 45, "Thermals"),
        Task("interrupt_latency", "Perf sampling-rate adjustment messages", "journalctl --since '30 days ago' -k --no-pager -o short-iso-precise | grep -iE 'perf: interrupt took too long|perf: interrupt.*lowering.*sample_rate' | tail -500", 45, "Software"),
        Task("rpm_kernel_graphics", "Installed kernel, graphics and desktop packages", "rpm -qa | grep -E '^(kernel|mesa|linux-firmware|kwin|kscreen|plasma|google-chrome|pipewire|wireplumber)' | sort", 35, "Software"),
        Task("dnf_history", "Recent package transactions", ["dnf", "history", "list"], 45, "Software"),
        Task("rpm_recent", "Recently installed or upgraded packages", "rpm -qa --last | head -140", 35, "Software"),
        Task("selinux_avc", "SELinux denials this boot", "journalctl -b 0 --no-pager -o short-iso-precise | grep -iE 'avc: +denied|SELinux is preventing' | tail -600", 35, "Software"),
    ]
    if shutil.which("abrt-cli", path=_safe_env()["PATH"]):
        tasks.append(Task("abrt", "ABRT detected problems", ["abrt-cli", "list"], 35, "Software"))
    if shutil.which("ras-mc-ctl", path=_safe_env()["PATH"]):
        tasks.append(Task("ras_errors", "Stored RAS/EDAC errors", ["ras-mc-ctl", "--errors"], 35, "Memory"))
    if shutil.which("edac-util", path=_safe_env()["PATH"]):
        tasks.append(Task("edac", "EDAC memory-controller counters", ["edac-util", "-v"], 25, "Memory"))
    if shutil.which("btrfs", path=_safe_env()["PATH"]):
        tasks.extend([
            Task("btrfs_stats", "Btrfs device error counters", ["btrfs", "device", "stats", "/"], 25, "Storage"),
            Task("btrfs_scrub", "Btrfs scrub status", ["btrfs", "scrub", "status", "/"], 25, "Storage"),
        ])
    for index, device in enumerate(discover_smart_devices()):
        tasks.append(Task(f"smart_{index}", f"SMART health: {device}", ["smartctl", "-x", device], 75, "Storage"))
    for index, device in enumerate(discover_nvme_devices()):
        tasks.append(Task(f"nvme_{index}", f"NVMe health: {device}", ["nvme", "smart-log", device], 40, "Storage"))
    if mode == "full":
        if shutil.which("fwts", path=_safe_env()["PATH"]):
            tasks.append(Task("fwts", "Firmware Test Suite", ["fwts", "--batch", "--stdout-summary"], 300, "Firmware"))
        tasks.extend([
            Task("dnf_check", "Package dependency consistency", ["dnf", "check"], 220, "Software"),
            Task("rpm_verify", "RPM file verification", "rpm -Va 2>&1 | head -6000", 300, "Software"),
            Task("systemd_blame", "Slowest boot services", ["systemd-analyze", "blame", "--no-pager"], 40, "Software"),
            Task("network_health", "NetworkManager state", ["nmcli", "-f", "STATE,CONNECTIVITY", "general"], 20, "PCIe / Network"),
            Task("resolver", "DNS resolver statistics", ["resolvectl", "statistics"], 25, "PCIe / Network"),
        ])
    return tasks


def add_virtual_checks(checks: dict[str, Any]) -> None:
    gpu_chunks = []
    for error_file in glob.glob("/sys/class/drm/card*/error"):
        gpu_chunks.append(f"--- {error_file} ---\n{read_file(error_file, 500_000)}")
    checks["gpu_error_state"] = {
        "title": "Current GPU error state",
        "category": "Graphics",
        "command": "read /sys/class/drm/card*/error",
        "status": "ok",
        "returncode": 0,
        "duration_seconds": 0,
        "output": "\n".join(gpu_chunks) if gpu_chunks else "No DRM error-state files exposed.",
    }
    pstore_chunks = []
    for item in glob.glob("/sys/fs/pstore/*"):
        pstore_chunks.append(f"--- {item} ---\n{read_file(item, 500_000)}")
    checks["pstore"] = {
        "title": "Persistent firmware/kernel crash records",
        "category": "Software",
        "command": "read /sys/fs/pstore",
        "status": "ok",
        "returncode": 0,
        "duration_seconds": 0,
        "output": "\n".join(pstore_chunks) if pstore_chunks else "No pstore crash records found.",
    }
    canary = Path("/var/log/fedora-crash-doctor/canary.log")
    checks["canary_log"] = {
        "title": "System canary snapshots",
        "category": "Software",
        "command": f"read {canary}",
        "status": "ok" if canary.exists() else "not_available",
        "returncode": 0,
        "duration_seconds": 0,
        "output": tail_file(canary, 1200) if canary.exists() else "System canary is not enabled.",
    }


def tail_file(path: Path, lines: int) -> str:
    try:
        data = path.read_text(errors="replace").splitlines()
        return "\n".join(data[-lines:])
    except Exception as exc:
        return f"Unable to read {path}: {exc}"


def evidence_lines(text: str, pattern: str, limit: int = 10) -> list[str]:
    regex = re.compile(pattern, re.I)
    found = []
    for line in text.splitlines():
        if regex.search(line):
            found.append(line.strip())
            if len(found) >= limit:
                break
    return found


def _make_finding(
    finding_id: str,
    severity: str,
    category: str,
    title: str,
    explanation: str,
    evidence: list[str],
    scope: str,
    confidence: str = "moderate",
) -> dict[str, Any]:
    return {
        "id": finding_id,
        "severity": severity,
        "category": category,
        "title": title,
        "explanation": explanation,
        "evidence": evidence,
        "scope": scope,
        "confidence": confidence,
    }


def analyse(checks: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    prev = "\n".join(checks.get(k, {}).get("output", "") for k in (
        "previous_errors", "previous_kernel_tail", "previous_boot_tail",
        "display_previous", "hardware_errors_previous", "oom_previous", "thermal_previous"
    ))
    history = "\n".join(checks.get(k, {}).get("output", "") for k in (
        "display_history", "hardware_errors_history", "oom_history", "interrupt_latency"
    ))
    all_text = "\n".join(str(v.get("output", "")) for v in checks.values())
    findings: list[dict[str, Any]] = []

    rules = [
        ("kernel_panic", "critical", "Software", "Kernel panic or lockup recorded",
         r"kernel panic|not syncing|watchdog:.*(?:hard lockup|soft lockup)",
         "The kernel explicitly reported a panic or watchdog lockup.", "high"),
        ("uncorrectable_hardware", "critical", "Memory", "Uncorrectable hardware error",
         r"uncorrectable.*(?:error|fatal)|hardware error.*uncorrected|mce:.*fatal|machine check.*fatal",
         "An uncorrectable CPU, RAM or PCIe hardware event can directly stop the system.", "high"),
        ("storage_failure", "critical", "Storage", "Storage failure indicators",
         r"SMART overall-health.*FAILED|SMART Health Status:.*(?:BAD|FAILED)|critical_warning\s*:\s*[1-9]|medium error|I/O error.*(?:nvme|sd[a-z])",
         "A drive or storage path reported a potentially serious reliability problem.", "high"),
        ("intel_display", "warning", "Graphics", "Intel graphics/display pipeline errors",
         r"i915.*atomic update failure|GL_FRAMEBUFFER_INCOMPLETE_ATTACHMENT|i915.*GPU HANG|i915.*reset",
         "Intel DRM/KWin display failures can cause black screens, compositor stalls or a full freeze.", "moderate"),
        ("other_gpu", "warning", "Graphics", "GPU reset or timeout",
         r"amdgpu.*(?:reset|timeout|ring.*stalled)|nouveau.*(?:timeout|fault)|nvidia.*Xid|drm.*flip_done timed out",
         "A graphics driver or GPU timeout was recorded.", "moderate"),
        ("oom", "warning", "Memory", "Memory exhaustion",
         r"out of memory|oom-kill|killed process|systemd-oomd.*killed",
         "The machine ran out of usable memory or an OOM service terminated processes.", "high"),
        ("pcie", "warning", "PCIe / Network", "PCIe bus reliability errors",
         r"pcie bus error|aer:.*error|bad dllp|receiver error",
         "PCIe errors can identify a device, link, power-management or signal-integrity problem.", "moderate"),
        ("filesystem", "warning", "Storage", "Filesystem or storage-path errors",
         r"BTRFS.*(?:error|corrupt)|EXT4-fs error|XFS.*corruption|blk_update_request.*I/O error|nvme.*timeout",
         "The filesystem or storage path recorded errors that warrant backup and testing.", "moderate"),
        ("thermal", "warning", "Thermals", "Thermal protection event",
         r"critical temperature|overheat|thermal.*shutdown|temperature above threshold",
         "A serious overheating or thermal-protection event was recorded.", "high"),
    ]
    for fid, severity, category, title, pattern, explanation, confidence in rules:
        lines = evidence_lines(prev, pattern)
        scope = "this_incident"
        if not lines:
            lines = evidence_lines(history if fid in {"intel_display", "other_gpu", "oom", "pcie"} else all_text, pattern)
            scope = "historical"
        if lines:
            findings.append(_make_finding(fid, severity, category, title, explanation, lines, scope, confidence))

    inventory = parse_lspci_inventory(checks.get("pci", {}).get("output", ""))
    pcie_hits = extract_pcie_devices(
        checks.get("hardware_errors_history", {}).get("output", "") + "\n" +
        checks.get("hardware_errors_previous", {}).get("output", ""),
        inventory,
    )
    repeated = {address: item for address, item in pcie_hits.items() if item["count"] >= 2}
    if repeated:
        evidence = []
        device_details = []
        for address, item in sorted(repeated.items(), key=lambda pair: pair[1]["count"], reverse=True):
            device_details.append({"address": address, **item})
            evidence.append(
                f"{address} — {item['description']} — driver {item['driver']} — {item['count']} events"
            )
            evidence.extend(item["lines"][-3:])
        findings.append({
            **_make_finding(
                "repeated_pcie_device", "warning", "PCIe / Network",
                "The same PCIe device repeatedly reported bus errors",
                "Repeated corrected errors from one address are more actionable than an isolated generic AER line.",
                evidence[:14], "historical", "moderate"
            ),
            "devices": device_details,
        })

    corrected = evidence_lines(all_text, r"severity=Corrected|severity=Correctable|corrected error", 10)
    if corrected:
        findings.append(_make_finding(
            "corrected_events", "info", "PCIe / Network", "Corrected hardware or PCIe events",
            "The hardware recovered these events. Repetition on one device still deserves attention.",
            corrected, "historical", "high"
        ))

    crash_lines = evidence_lines(checks.get("boot_history", {}).get("output", ""), r"\s-crash\s|\bcrash\s+\(", 8)
    if crash_lines:
        findings.append(_make_finding(
            "unclean_boot", "info", "Software", "A previous boot ended without a clean shutdown",
            "Boot accounting marks one or more sessions as crashed rather than normally shut down.",
            crash_lines, "this_incident", "high"
        ))

    perf_lines = evidence_lines(checks.get("interrupt_latency", {}).get("output", ""), r"perf: interrupt took too long", 12)
    if perf_lines:
        findings.append(_make_finding(
            "perf_sampling_adjustment", "info", "Software", "Kernel perf reduced its sampling rate",
            "These messages mean perf sampling exceeded its time allowance. They are context, not a dependable crash predictor by themselves.",
            perf_lines, "historical", "high"
        ))

    if not evidence_lines(checks.get("oom_previous", {}).get("output", ""), r"out of memory|oom-kill|killed process"):
        findings.append(_make_finding(
            "no_oom", "info", "Memory", "No logged memory-exhaustion event for the previous boot",
            "The previous-boot journal did not contain a clear OOM-kill signature.", [], "this_incident", "high"
        ))
    if "No pstore crash records found" in checks.get("pstore", {}).get("output", ""):
        findings.append(_make_finding(
            "no_pstore", "info", "Software", "No persistent pstore crash record found",
            "Firmware-backed pstore did not preserve a panic or oops record.", [], "this_incident", "high"
        ))

    context = {
        "pci_inventory": inventory,
        "pcie_devices": pcie_hits,
        "hard_crash": bool(crash_lines),
        "has_gpu_errors": any(f["id"] in {"intel_display", "other_gpu"} for f in findings),
        "has_oom": any(f["id"] == "oom" for f in findings),
        "has_thermal": any(f["id"] == "thermal" for f in findings),
        "has_storage": any(f["id"] in {"storage_failure", "filesystem"} for f in findings),
        "has_panic": any(f["id"] == "kernel_panic" for f in findings),
    }
    order = {"critical": 0, "warning": 1, "info": 2}
    findings.sort(key=lambda item: (order[item["severity"]], item["scope"] != "this_incident", item["title"]))
    return findings, context


_TS_RX = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?[+-]\d{4})\s+(.*)$")


def parse_journal_time(line: str) -> datetime | None:
    match = _TS_RX.match(line)
    if not match:
        return None
    raw = match.group(1)
    try:
        return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%S.%f%z")
    except ValueError:
        try:
            return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%S%z")
        except ValueError:
            return None


def build_timeline(checks: dict[str, Any]) -> list[dict[str, Any]]:
    lines = checks.get("previous_boot_tail", {}).get("output", "").splitlines()
    parsed = [(parse_journal_time(line), line) for line in lines]
    parsed = [(ts, line) for ts, line in parsed if ts is not None]
    if not parsed:
        return []
    end_time = max(ts for ts, _ in parsed)
    patterns = [
        ("Graphics", r"i915|amdgpu|nvidia|nouveau|atomic update failure|framebuffer|kwin|context provider|compositor"),
        ("Memory", r"out of memory|oom-kill|killed process|edac|mce:"),
        ("PCIe / Network", r"pcie bus error|aer:|bad dllp|receiver error|failed to resolve|NetworkManager"),
        ("Thermals", r"thermal|overheat|throttl|critical temperature"),
        ("Storage", r"btrfs.*error|nvme.*(?:error|timeout)|I/O error|smart"),
        ("Software", r"segfault|core dump|watchdog|panic|wireplumber|pipewire|chrome"),
    ]
    events: list[dict[str, Any]] = []
    seen: set[str] = set()
    for ts, line in parsed:
        category = None
        for candidate, pattern in patterns:
            if re.search(pattern, line, re.I):
                category = candidate
                break
        if not category:
            continue
        compact = re.sub(r"^\S+\s+", "", line).strip()
        signature = re.sub(r"\d+", "#", compact)[:160]
        if signature in seen:
            continue
        seen.add(signature)
        delta = end_time - ts
        proximity = "Immediately before crash" if delta <= timedelta(minutes=10) else "Earlier in same boot"
        events.append({
            "timestamp": ts.isoformat(timespec="seconds"),
            "category": category,
            "summary": compact[:280],
            "evidence": line,
            "proximity": proximity,
            "seconds_before_last_log": max(0, int(delta.total_seconds())),
        })
    events = sorted(events, key=lambda item: item["timestamp"])[-80:]
    events.append({
        "timestamp": end_time.isoformat(timespec="seconds"),
        "category": "Crash boundary",
        "summary": "The previous journal stops here; the next boot was recorded as unclean/crashed.",
        "evidence": parsed[-1][1],
        "proximity": "Crash boundary",
        "seconds_before_last_log": 0,
    })
    return events


def analyse_canary(checks: dict[str, Any]) -> dict[str, Any]:
    text = checks.get("canary_log", {}).get("output", "")
    rows = []
    for line in text.splitlines():
        try:
            row = json.loads(line)
        except Exception:
            continue
        if isinstance(row, dict) and "ts" in row:
            rows.append(row)
    rows = rows[-240:]
    result = {"samples": rows, "interpretation": "No canary samples available."}
    if not rows:
        return result
    stale = [
        row for row in rows[-20:]
        if (row.get("desktop_heartbeat_age_s") or 0) > 20 or row.get("kwin_ok") is False
    ]
    if stale:
        result["interpretation"] = (
            "The system canary continued while the desktop/KWin heartbeat became stale or failed. "
            "That pattern supports a compositor/session-level freeze more than immediate total power loss."
        )
    else:
        result["interpretation"] = (
            "The latest system and desktop heartbeat samples remained aligned. If both stop together at a future crash, "
            "that supports a kernel, firmware, power or total-system lock rather than only KWin."
        )
    return result


def confidence_label(score: float) -> str:
    if score >= 0.75:
        return "high"
    if score >= 0.45:
        return "moderate"
    return "low"


def numeric_score(item: dict[str, Any]) -> float:
    try:
        return float(item.get("score") or 0)
    except (TypeError, ValueError):
        return 0.0


def build_hypotheses(findings: list[dict[str, Any]], context: dict[str, Any], checks: dict[str, Any], canary: dict[str, Any]) -> list[dict[str, Any]]:
    ids = {item["id"] for item in findings}
    hypotheses: list[dict[str, Any]] = []

    graphics_support = []
    graphics_against = []
    score = 0.0
    if "intel_display" in ids or "other_gpu" in ids:
        score += 0.42
        graphics_support.append("Graphics/DRM errors were recorded in or around the affected boot.")
    previous = checks.get("previous_boot_tail", {}).get("output", "")
    if re.search(r"kwin|GL_FRAMEBUFFER_INCOMPLETE_ATTACHMENT", previous, re.I):
        score += 0.18
        graphics_support.append("KWin/framebuffer errors were present.")
    if re.search(r"context provider failed|compositor.*active for too long", previous, re.I):
        score += 0.15
        graphics_support.append("Chrome compositor or video-capture graphics contexts were failing shortly before the reboot.")
    if context["hard_crash"]:
        score += 0.10
        graphics_support.append("The session ended as an unclean hard crash rather than a normal application exit.")
    if "No error state collected" in checks.get("gpu_error_state", {}).get("output", ""):
        graphics_against.append("The current boot exposes no preserved formal GPU-hang dump.")
    if score:
        hypotheses.append({
            "rank": 0,
            "title": "Intel/KWin display-stack freeze",
            "category": "Graphics",
            "score": round(min(score, 0.95), 2),
            "confidence": confidence_label(score),
            "supports": graphics_support,
            "against": graphics_against or ["No decisive counter-evidence was collected."],
            "next_test": "Run the next important call with one monitor connected directly at 8-bit SDR/60 Hz, then compare a new scan.",
            "would_confirm": "The errors disappear and the crash does not recur in the reduced display configuration, or a future crash preserves an i915/KWin GPU reset/hang near the boundary.",
            "would_weaken": "The same crash occurs with one monitor and no graphics errors, while another subsystem records a closer fault.",
        })

    repeated = next((f for f in findings if f["id"] == "repeated_pcie_device"), None)
    if repeated:
        device = repeated.get("devices", [{}])[0]
        pcie_score = 0.50
        against = ["The logged events were corrected rather than fatal."]
        if context["hard_crash"]:
            pcie_score += 0.05
        hypotheses.append({
            "rank": 0,
            "title": f"PCIe link/device instability: {device.get('description', 'unknown device')}",
            "category": "PCIe / Network",
            "score": round(pcie_score, 2),
            "confidence": confidence_label(pcie_score),
            "supports": [
                f"Address {device.get('address')} using driver {device.get('driver')} recorded {device.get('count')} matching bus events.",
                "The parser matched the PCI address anywhere in the AER line and joined it to lspci.",
            ],
            "against": against,
            "next_test": "Update firmware, reseat/replace the affected adapter or disable its PCIe power saving for an A/B test; use Ethernet temporarily if it is the Wi-Fi card.",
            "would_confirm": "Errors recur on the same address and stop when the device is removed, replaced or bypassed.",
            "would_weaken": "The same address remains quiet across repeated crashes while another component records immediate faults.",
        })

    if context["hard_crash"] and not context["has_panic"]:
        power_score = 0.30
        support = ["The journal ended abruptly and no normal shutdown was recorded."]
        against = ["An abrupt journal ending also occurs during a GPU/kernel deadlock, so this is not specific to power or firmware."]
        if "No pstore crash records found" in checks.get("pstore", {}).get("output", ""):
            support.append("No pstore panic/oops record survived the reboot.")
        hypotheses.append({
            "rank": 0,
            "title": "Kernel, firmware, motherboard or power-level lock",
            "category": "Firmware",
            "score": power_score,
            "confidence": confidence_label(power_score),
            "supports": support,
            "against": against,
            "next_test": "Enable kdump, persistent capture and both heartbeats; if it happens again, compare the final canary and desktop-heartbeat times.",
            "would_confirm": "Both heartbeats stop together with no userspace precursor, or kdump/pstore captures a kernel/firmware fault.",
            "would_weaken": "The system canary keeps running while only the desktop heartbeat fails.",
        })

    # Explicitly rank currently unsupported common explanations low.
    hypotheses.extend([
        {
            "rank": 0,
            "title": "Out-of-memory crash",
            "category": "Memory",
            "score": 0.10 if not context["has_oom"] else 0.8,
            "confidence": "low" if not context["has_oom"] else "high",
            "supports": ["No supporting OOM signature was found."] if not context["has_oom"] else ["OOM-kill signatures were recorded."],
            "against": ["The previous boot contained no clear OOM-kill event."] if not context["has_oom"] else [],
            "next_test": "Keep the canary enabled to preserve memory and PSI pressure immediately before another event.",
            "would_confirm": "A future event shows severe memory PSI, exhausted swap, or an OOM kill at the crash boundary.",
            "would_weaken": "Memory pressure remains low immediately before repeated crashes.",
        },
        {
            "rank": 0,
            "title": "Thermal shutdown",
            "category": "Thermals",
            "score": 0.08 if not context["has_thermal"] else 0.8,
            "confidence": "low" if not context["has_thermal"] else "high",
            "supports": ["No supporting thermal shutdown signature was found."] if not context["has_thermal"] else ["Thermal protection messages were recorded."],
            "against": ["The logs did not show a critical temperature or thermal shutdown."] if not context["has_thermal"] else [],
            "next_test": "Use the canary and a deliberate CPU test while watching sensors, only when interruption is acceptable.",
            "would_confirm": "Temperatures reach the platform limit or the kernel records throttling/thermal shutdown at the boundary.",
            "would_weaken": "Temperatures stay well below limits through reproduction attempts.",
        },
    ])

    hypotheses.sort(key=numeric_score, reverse=True)
    for index, item in enumerate(hypotheses, start=1):
        item["rank"] = index
    return hypotheses


def category_status(findings: list[dict[str, Any]], checks: dict[str, Any]) -> dict[str, dict[str, str]]:
    categories = ["Graphics", "Memory", "Storage", "Thermals", "PCIe / Network", "Firmware", "Software"]
    result = {}
    for category in categories:
        related = [f for f in findings if f["category"] == category]
        if any(f["severity"] == "critical" for f in related):
            result[category] = {"status": "critical", "label": "Critical"}
        elif any(f["severity"] == "warning" for f in related):
            result[category] = {"status": "warning", "label": "Needs attention"}
        else:
            related_checks = [c for c in checks.values() if c.get("category") == category]
            if any(c.get("status") == "ok" for c in related_checks):
                result[category] = {"status": "passed", "label": "No fault found"}
            elif related_checks:
                result[category] = {"status": "not_checked", "label": "Scan incomplete"}
            else:
                result[category] = {"status": "not_checked", "label": "Not checked"}
    return result


def build_overall(hypotheses: list[dict[str, Any]], context: dict[str, Any]) -> dict[str, str]:
    if not hypotheses:
        return {
            "title": "No leading cause identified",
            "confidence": "low",
            "summary": "The scan did not collect enough evidence to rank a likely cause.",
        }
    top = hypotheses[0]
    if numeric_score(top) < 0.25:
        return {
            "title": "No evidence-backed leading cause yet",
            "confidence": "low",
            "summary": "The scan did not find enough positive evidence to rank a likely cause. Low-scoring alternatives remain listed only as things the current evidence does not support.",
        }
    absent = []
    if not context["has_oom"]:
        absent.append("no logged OOM event")
    if not context["has_thermal"]:
        absent.append("no thermal shutdown")
    if not context["has_storage"]:
        absent.append("no clear storage failure")
    suffix = f" The scan also found {', '.join(absent)}." if absent else ""
    return {
        "title": top["title"],
        "confidence": top["confidence"],
        "summary": f"Leading hypothesis: {top['title']} ({top['confidence']} confidence).{suffix}",
    }


def collect(mode: str = "quick", baseline_path: str | None = None, progress: Progress | None = None) -> dict[str, Any]:
    if mode not in {"quick", "full"}:
        raise ValueError("mode must be quick or full")
    metadata = _metadata()
    metadata["mode"] = mode
    tasks = build_tasks(mode)
    checks = CheckRunner(tasks, progress).execute()
    add_virtual_checks(checks)
    findings, context = analyse(checks)
    timeline = build_timeline(checks)
    canary = analyse_canary(checks)
    hypotheses = build_hypotheses(findings, context, checks, canary)

    baseline = load_baseline(baseline_path)
    now = metadata["generated"]
    for finding in findings:
        prior = baseline.get(finding["id"])
        finding["status"] = "recurring" if prior else "new"
        finding["first_seen"] = prior.get("first_seen") if prior else now

    counts = {
        "critical": sum(f["severity"] == "critical" for f in findings),
        "warning": sum(f["severity"] == "warning" for f in findings),
        "info": sum(f["severity"] == "info" for f in findings),
    }
    return {
        "schema": 3,
        "metadata": metadata,
        "counts": counts,
        "overall": build_overall(hypotheses, context),
        "categories": category_status(findings, checks),
        "findings": findings,
        "hypotheses": hypotheses,
        "timeline": timeline,
        "canary": canary,
        "checks": checks,
        "test_targets": {
            "smart_devices": discover_smart_devices(),
            "btrfs_root": Path("/").exists() and shutil.which("btrfs", path=_safe_env()["PATH"]) is not None,
        },
        "limitations": [
            "A total hard lock can prevent the kernel from writing its final error to disk.",
            "Kdump captures kernel panics but may not capture power loss, firmware lockups or every GPU deadlock.",
            "A clean scan cannot prove that intermittent RAM, power, motherboard, cable, dock or peripheral faults are absent.",
            "Stress, memory, disk self-tests and filesystem scrubs are separate, confirmed actions and are never run by a scan.",
            "Ranked hypotheses are evidence-weighted explanations, not certainty or a substitute for hardware service.",
        ],
    }


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["quick", "full"], default="quick")
    parser.add_argument("--output", required=True)
    parser.add_argument("--baseline")
    args = parser.parse_args()
    report = collect(args.mode, args.baseline)
    Path(args.output).write_text(json.dumps(report, indent=2, ensure_ascii=False))
