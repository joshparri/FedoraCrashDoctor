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
            "likely_role": pci_device_role(inventory.get(address, {}).get("description", ""), inventory.get(address, {}).get("driver", "")),
            "lines": [],
        })
        item["count"] += 1
        if len(item["lines"]) < 12:
            item["lines"].append(line.strip())
    return hits


def pci_device_role(description: str, driver: str) -> str:
    text = f"{description} {driver}".lower()
    if any(token in text for token in ("wireless", "wi-fi", "wifi", "wlan", "802.11", "rtw", "iwl", "ath")):
        return "Wi-Fi card"
    if any(token in text for token in ("ethernet", "network", "realtek", "intel corporation ethernet")):
        return "network adapter"
    if any(token in text for token in ("usb", "xhci")):
        return "USB controller, dock or hub path"
    if any(token in text for token in ("vga", "display", "graphics", "nvidia", "amd/ati", "intel corporation hd graphics")):
        return "graphics adapter"
    if any(token in text for token in ("nvme", "sata", "storage")):
        return "storage controller"
    return "PCIe device"


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
        ("intel_display", "warning", "Graphics", "Intel graphics/display pipeline errors",
         r"(?:i915|xe\s).*atomic update failure|GL_FRAMEBUFFER_INCOMPLETE_ATTACHMENT|(?:i915|xe\s).*GPU HANG|(?:i915|xe\s).*reset",
         "Intel DRM/KWin display failures can cause black screens, compositor stalls or a full freeze.", "moderate"),
        ("other_gpu", "warning", "Graphics", "GPU reset or timeout",
         r"amdgpu.*(?:reset|timeout|ring.*stalled)|nouveau.*(?:timeout|fault)|nvidia.*Xid|drm.*flip_done timed out",
         "A graphics driver or GPU timeout was recorded.", "moderate"),
        ("wayland", "warning", "Graphics", "Wayland compositor or session crash",
         r"wayland.*(?:crash|fatal|error(?!\s*(?:disconnect|terminate)))|kwin_wayland.*(?:segfault|core dump|aborted)",
         "The Wayland display server or compositor reported a crash or fatal error.", "moderate"),
        ("oom", "warning", "Memory", "Memory exhaustion",
         r"out of memory|oom-kill|killed process|systemd-oomd.*killed",
         "The machine ran out of usable memory or an OOM service terminated processes.", "high"),
        ("pcie", "warning", "PCIe / Network", "PCIe bus reliability errors",
         r"pcie bus error|aer:.*error|bad dllp|receiver error",
         "PCIe errors can identify a device, link, power-management or signal-integrity problem.", "moderate"),
        ("thermal", "warning", "Thermals", "Thermal protection event",
         r"critical temperature|overheat|thermal.*shutdown|temperature above threshold",
         "A serious overheating or thermal-protection event was recorded.", "high"),
    ]
    for fid, severity, category, title, pattern, explanation, confidence in rules:
        lines = evidence_lines(prev, pattern)
        scope = "this_incident"
        if not lines:
            lines = evidence_lines(history if fid in {"intel_display", "other_gpu", "wayland", "oom", "pcie"} else all_text, pattern)
            scope = "historical"
        if lines:
            findings.append(_make_finding(fid, severity, category, title, explanation, lines, scope, confidence))

    tail_lines = checks.get("previous_boot_tail", {}).get("output", "").splitlines()
    parsed_tail = [(parse_journal_time(line), line) for line in tail_lines]
    parsed_tail = [(ts, line) for ts, line in parsed_tail if ts is not None]
    
    if parsed_tail:
        end_time = max(ts for ts, _ in parsed_tail)
        recent_failures = []
        for ts, line in parsed_tail:
            if end_time - ts <= timedelta(minutes=10):
                if re.search(r"systemd\[\d*\]:.*(?:Failed to start|failed with result|Main process exited, code=(?:exited|dumped), status=(?!0\b))", line, re.I):
                    recent_failures.append(line.strip())
        
        if recent_failures:
            findings.append(_make_finding(
                "failed_services", "warning", "Software", "Failed system services near crash",
                "One or more systemd services failed shortly before the crash boundary, which might have triggered downstream faults.",
                recent_failures[-10:], "this_incident", "moderate"
            ))

    storage_rx = re.compile(r"SMART overall-health.*FAILED|SMART Health Status:.*(?:BAD|FAILED)|critical_warning\s*:\s*[1-9]|medium error|I/O error|BTRFS.*(?:error|corrupt)|EXT4-fs error|XFS.*corruption|blk_update_request.*I/O error|nvme.*timeout|link down|resetting", re.I)
    disk_events: dict[str, list[str]] = {}
    for line in evidence_lines(all_text, storage_rx.pattern, 50):
        dev_match = re.search(r"(?:dev(?:ice)?\s+|FAT-fs\s*\()([a-z0-9]+)\b", line, re.I)
        dev = dev_match.group(1) if dev_match else "unknown"
        disk_events.setdefault(dev, []).append(line.strip())

    lsblk_out = checks.get("block", {}).get("output", "")
    for dev, lines in disk_events.items():
        base_dev = re.sub(r"p?\d+$", "", dev) if dev.startswith("nvme") else dev.rstrip("0123456789")
        is_removable = bool(re.search(fr"\b{base_dev}\b.*usb", lsblk_out, re.I) or re.search(fr"\[{base_dev}\].*removable disk", all_text, re.I))
        has_smart = any(re.search(r"SMART|critical_warning", l, re.I) for l in lines)
        has_write_err = any(re.search(r"write|WRITE", l, re.I) for l in lines)
        has_read_err = any(re.search(r"read|READ", l, re.I) for l in lines)
        has_reset = any(re.search(r"reset|link down|timeout", l, re.I) for l in lines)
        has_disconnect = is_removable and bool(re.search(r"USB disconnect", all_text, re.I))

        severity = "warning"
        title = f"Storage errors on {dev}"
        explanation = f"The storage device {dev} reported errors."
        
        err_types = []
        if has_read_err: err_types.append("read errors")
        if has_write_err: err_types.append("write errors")
        if has_reset: err_types.append("link resets or timeouts")
        if not err_types: err_types.append("I/O or filesystem errors")
        
        if is_removable:
            title = f"Errors on removable device {dev}"
            explanation = f"A removable device ({dev}) reported {', '.join(err_types)}."
            if has_disconnect:
                explanation += " This likely coincides with an unsafe removal or transient connection loss."
                severity = "info"
            elif len(lines) == 1:
                severity = "info"
            if has_smart:
                severity = "critical"
                explanation += " It also reported SMART health failures, indicating hardware degradation."
        else:
            if has_smart:
                severity = "critical"
                title = f"Active failure on internal disk {dev}"
                explanation = f"The internal system disk {dev} reported SMART health failures. Immediate backup is recommended."
            elif len(lines) > 2:
                severity = "critical"
                title = f"Repeated errors on internal disk {dev}"
                explanation = f"The internal disk {dev} is experiencing repeated {', '.join(err_types)}. This indicates a current or repeated risk of data loss. Immediate backup is recommended."
            else:
                severity = "warning"
                title = f"Transient error on internal disk {dev}"
                explanation = f"The internal disk {dev} logged {', '.join(err_types)}. Backup and filesystem checks are advised, but it may be a single historical event."

        if dev == "unknown":
            title = "Unidentified storage device errors"
            explanation = "Storage errors were logged, but the exact physical device could not be identified."
            severity = "warning"
            if has_smart:
                severity = "critical"
                explanation += " SMART health failures were detected. Immediate backup of important data is recommended."

        findings.append(_make_finding(
            f"storage_{dev}", severity, "Storage", title, explanation, lines[:10], "historical",
            "high" if len(lines) > 2 or has_smart else "moderate"
        ))

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
                f"{address} — {item['likely_role']} — {item['description']} — driver {item['driver']} — {item['count']} events"
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
        "has_gpu_errors": any(f["id"] in {"intel_display", "other_gpu", "wayland"} for f in findings),
        "has_oom": any(f["id"] == "oom" for f in findings),
        "has_thermal": any(f["id"] == "thermal" for f in findings),
        "has_storage": any(f["id"] in {"storage_failure", "filesystem"} for f in findings),
        "has_panic": any(f["id"] == "kernel_panic" for f in findings),
    }
    order = {"critical": 0, "warning": 1, "info": 2}
    findings.sort(key=lambda item: (order[item["severity"]], item["scope"] != "this_incident", item["title"]))
    return findings, context


_TS_RX = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))\s+(.*)$")


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
        ("Graphics", r"i915|xe |amdgpu|nvidia|nouveau|atomic update|framebuffer|kwin|context provider|compositor|wayland"),
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




def parse_boots_from_journal(checks):
    boots = {}
    out = checks.get("journal_boots", {}).get("output", "")
    for line in out.splitlines():
        # Handle variations in locale/timezone by just extracting the YYYY-MM-DD HH:MM:SS
        import re
        from datetime import datetime
        m = re.match(r"^\s*([-\d]+)\s+([a-f0-9]{32})\s+.*?(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}).*?(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})", line)
        if m:
            idx, boot_id, start_str, end_str = m.groups()
            boots[idx] = {
                "idx": idx,
                "id": boot_id,
                "start": datetime.strptime(start_str, "%Y-%m-%d %H:%M:%S"),
                "end": datetime.strptime(end_str, "%Y-%m-%d %H:%M:%S"),
            }
    return boots

def get_boot_for_ts(ts, boots):
    if not ts: return "unknown"
    from datetime import timedelta
    naive_ts = ts.replace(tzinfo=None)
    for b in boots.values():
        if b["start"] - timedelta(minutes=5) <= naive_ts <= b["end"] + timedelta(minutes=5):
            return b["idx"]
    return "unknown"

def build_incidents(findings, checks):
    boots = parse_boots_from_journal(checks)
    import re
    from datetime import datetime, timedelta
    
    # 1. Identify failure boundaries
    boundaries = []
    
    # Unclean boots
    crash_lines = evidence_lines(checks.get("boot_history", {}).get("output", ""), r"\s-crash\s|crash\s+\(", 20)
    if crash_lines and "-1" in boots:
        boundaries.append({"boot": "-1", "type": "unclean shutdown", "ts": boots["-1"]["end"]})
        
    unclean_f = next((f for f in findings if f["id"] == "unclean_boot"), None)
    if unclean_f:
        for line in unclean_f.get("evidence", []):
            m = re.search(r"([A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2})\s+-\s+crash", line)
            if m:
                try:
                    dt = datetime.strptime(m.group(1), "%a %b %d %H:%M")
                    for b in boots.values():
                        if b["end"].month == dt.month and b["end"].day == dt.day and b["end"].hour == dt.hour and abs(b["end"].minute - dt.minute) <= 5:
                            boundaries.append({"boot": b["idx"], "type": "unclean shutdown", "ts": b["end"]})
                            break
                except ValueError:
                    pass
    
    # Compositor crashes / OOM kills
    for f in findings:
        if f["id"] in {"wayland", "oom"}:
            for line in f.get("evidence", []):
                ts = parse_journal_time(line)
                b = get_boot_for_ts(ts, boots)
                if b != "unknown" and ts:
                    boundaries.append({"boot": b, "type": "OOM" if f["id"] == "oom" else "compositor crash", "ts": ts.replace(tzinfo=None)})
                    
    # Group into incident windows (collapse boundaries in same boot if < 15 mins)
    incidents = []
    for boot_idx, b_data in boots.items():
        boot_bounds = sorted([bd for bd in boundaries if bd["boot"] == boot_idx], key=lambda x: x["ts"])
        merged = []
        for bd in boot_bounds:
            if not merged:
                merged.append(bd)
            elif (bd["ts"] - merged[-1]["ts"]).total_seconds() < 900:
                # keep latest
                merged[-1] = bd
            else:
                merged.append(bd)
                
        if not merged and boot_idx == "0":
            # Active boot is an incident even without crash
            merged = [{"boot": "0", "type": "active session", "ts": boots["0"]["end"]}]
            
        for idx, bd in enumerate(merged):
            # Window is bd["ts"] - 15 mins to bd["ts"]
            w_start = bd["ts"] - timedelta(minutes=15)
            w_end = bd["ts"] + timedelta(minutes=1)
            incidents.append({
                "boot": bd["boot"],
                "start": w_start,
                "end": w_end,
                "boundary": bd["type"],
                "events": [],
                "symptoms": {}
            })
            
    # Assign evidence to incidents
    unattributed = []
    for f in findings:
        if f["id"] in {"no_oom", "no_pstore", "corrected_events", "perf_sampling_adjustment"}:
            continue
        for line in f.get("evidence", []):
            ts = parse_journal_time(line)
            cmd = next((v.get("command", "") for v in checks.values() if v.get("output") and line in v["output"]), "unknown")
            event = {"finding": f, "line": line, "timestamp": ts.isoformat() if ts else None, "command": cmd}
            
            assigned = False
            if ts:
                naive_ts = ts.replace(tzinfo=None)
                # Find incident window
                for inc in incidents:
                    if inc["start"] <= naive_ts <= inc["end"]:
                        inc["events"].append(event)
                        assigned = True
                        break
            if not assigned:
                # If no timestamp, DO NOT GUESS. Put in unattributed.
                unattributed.append(event)
                
    # Now evaluate each incident
    report_incidents = []
    for inc in incidents:
        if not inc["events"] and inc["boundary"] == "active session":
            continue
            
        symptoms = {}
        for e in inc["events"]:
            fid = e["finding"]["id"]
            if fid not in symptoms:
                symptoms[fid] = {"finding": e["finding"], "evidence": []}
            symptoms[fid]["evidence"].append(e)
            
        context = {
            "hard_crash": inc["boundary"] == "unclean shutdown",
            "has_panic": "kernel_panic" in symptoms,
            "has_oom": "oom" in symptoms,
            "has_thermal": "thermal" in symptoms,
            "has_storage": any(k in {"storage_failure", "filesystem", "system_disk_error"} for k in symptoms),
        }
        
        hypotheses = []
        if any(k in {"intel_display", "other_gpu", "wayland"} for k in symptoms):
            score = 0.42
            supports = ["Graphics/DRM or Wayland errors were recorded near the boundary."]
            if context["hard_crash"]:
                score += 0.10
                supports.append("The session ended in an unclean crash.")
            hypotheses.append({
                "title": "Display-stack freeze or GPU hang",
                "category": "Graphics",
                "score": score,
                "confidence": confidence_label(score),
                "supports": supports,
                "against": [],
                "next_test": "Gather next crash log with minimal display configuration.",
            })
            
        if "repeated_pcie_device" in symptoms:
            score = 0.50
            supports = ["Repeated PCIe correctable errors were found."]
            against = ["The logged events were correctable, which rarely cause a hard lockup."]
            if context["hard_crash"] and not context["has_panic"]:
                score += 0.10
            hypotheses.append({
                "title": "PCIe link/device instability",
                "category": "PCIe / Network",
                "score": min(score, 0.9),
                "confidence": confidence_label(score),
                "supports": supports,
                "against": against,
                "next_test": "Monitor PCIe bus for uncorrectable errors during next crash.",
            })
            
        if context["has_storage"]:
            score = 0.60
            supports = ["System storage I/O or filesystem errors occurred."]
            if context["hard_crash"]:
                score += 0.20
            hypotheses.append({
                "title": "Storage or Filesystem failure",
                "category": "Storage",
                "score": min(score, 0.95),
                "confidence": confidence_label(score),
                "supports": supports,
                "against": [],
                "next_test": "Back up immediately and schedule a long SMART test.",
            })

        if context["has_oom"]:
            score = 0.8
            supports = ["The kernel explicitly killed processes due to out-of-memory."]
            if context["hard_crash"]:
                score += 0.10
            hypotheses.append({
                "title": "Out-of-memory crash",
                "category": "Memory",
                "score": min(score, 0.95),
                "confidence": confidence_label(score),
                "supports": supports,
                "against": [],
                "next_test": "Enable system canary and monitor memory pressure.",
            })
            
        if context["hard_crash"] and not hypotheses:
            hypotheses.append({
                "title": "Unknown Kernel, Firmware or Power Failure",
                "category": "Firmware",
                "score": 0.30,
                "confidence": "low",
                "supports": ["The system suffered an unclean shutdown (crash)."],
                "against": [],
                "next_test": "Enable kdump or netconsole to capture panics.",
            })
            
        hypotheses.sort(key=lambda h: h["score"], reverse=True)
        best = hypotheses[0] if hypotheses else None
        
        unrelated = []
        best_cat = best["category"] if best else None
        for fid, item in symptoms.items():
            f = item["finding"]
            # Exclude removable devices from causing a system crash
            if f["id"] in {"removable_drive_error", "unsafe_removal"}:
                unrelated.append(f["title"] + " (Removable/USB)")
            elif f["category"] != best_cat and fid not in {"unclean_boot", "no_oom", "no_pstore"}:
                unrelated.append(f["title"])
                
        # confidence explanation
        if not context["hard_crash"] and best:
            best["title"] += " (Active Warning, no crash recorded)"
            best["supports"].append("This boot is currently active or exited cleanly.")
        conf_exp = f"Ranked {best['confidence']} based on timing and severity." if best else "No evidence."
                
        boot_obj = boots.get(inc["boot"], {})
        report_incidents.append({
            "boot_id": boot_obj.get("id", "unknown"),
            "boot_index": inc["boot"],
            "incident_start": inc["start"].isoformat(),
            "incident_end": inc["end"].isoformat(),
            "failure_boundary": inc["boundary"],
            "timestamped_evidence": [e for e in inc["events"] if e["timestamp"]],
            "unattributed_evidence": [e for e in unattributed if e["finding"]["id"] in symptoms],
            "strongest_hypothesis": best["title"] if best else "Unknown",
            "supporting_evidence": best["supports"] if best else [],
            "unrelated_warnings": unrelated,
            "next_step": best["next_test"] if best else "Gather more evidence.",
            "confidence": best["confidence"] if best else "low",
            "confidence_explanation": conf_exp,
            "hypotheses": hypotheses
        })
        
    # global unattributed
    
    return report_incidents, unattributed

def build_overall(incidents):
    if not incidents:
        return {"title": "No incidents", "confidence": "low", "summary": "No incidents."}
    best_inc = incidents[-1]
    if not best_inc["hypotheses"]:
        return {"title": "No evidence-backed leading cause yet", "confidence": "low", "summary": "No cause."}
    top = best_inc["hypotheses"][0]
    return {
        "title": top["title"],
        "confidence": top["confidence"],
        "summary": f"Leading hypothesis: {top['title']} ({top['confidence']} confidence)."
    }


def category_status(findings, checks):
    categories = ["Graphics", "Memory", "Storage", "Thermals", "PCIe / Network", "Firmware", "Software"]
    result = {}
    for category in categories:
        related = [f for f in findings if f["category"] == category]
        if any(f["severity"] == "critical" for f in related):
            result[category] = {"status": "critical", "label": "Critical"}
        elif any(f["severity"] == "warning" for f in related):
            labels = {
                "Graphics": "Try display-safe mode",
                "PCIe / Network": "Check PCIe device",
                "Storage": "Back up and test drive",
                "Thermals": "Check cooling",
                "Memory": "Check memory pressure",
                "Firmware": "Check firmware",
                "Software": "Review crash logs",
            }
            result[category] = {"status": "warning", "label": labels.get(category, "Needs attention")}
        else:
            related_checks = [c for c in checks.values() if c.get("category") == category]
            if any(c.get("status") == "ok" for c in related_checks):
                result[category] = {"status": "passed", "label": "No fault found"}
            elif related_checks:
                result[category] = {"status": "not_checked", "label": "Scan incomplete"}
            else:
                result[category] = {"status": "not_checked", "label": "Not checked"}
    return result

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
    incidents, unattributed = build_incidents(findings, checks)

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
        "incidents": incidents,
        "overall": build_overall(incidents),
        "hypotheses": incidents[-1]["hypotheses"] if incidents else [],
        "categories": category_status(findings, checks),
        "findings": findings,
        
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
