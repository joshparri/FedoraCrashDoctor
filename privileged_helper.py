#!/usr/bin/python3
"""Locked-down privileged broker for Fedora Crash Doctor.

The GUI starts this exact root-owned executable through pkexec. Polkit asks once,
then the broker remains attached to that GUI process and accepts only the
whitelisted JSON actions below. It is not a shell and never executes user-
supplied commands or writes to user-supplied paths.
"""
from __future__ import annotations

import ctypes
import json
import os
import pwd
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

APP_DIR = Path(__file__).resolve().parent
SHARE_DIR = Path("/usr/share/fedora-crash-doctor")
sys.path.insert(0, str(APP_DIR))
if SHARE_DIR.exists():
    sys.path.insert(1, str(SHARE_DIR))
from collector import collect, discover_smart_devices  # noqa: E402
from version import app_version  # noqa: E402

STATE_DIR = Path("/var/lib/fedora-crash-doctor")
CONFIG_DIR = Path("/etc/fedora-crash-doctor")
LOG_DIR = Path("/var/log/fedora-crash-doctor")
SYSTEMD_DIR = Path("/usr/lib/systemd/system")
USER_SYSTEMD_DIR = Path("/usr/lib/systemd/user")
SAFE_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
MAX_REQUEST = 64 * 1024


def safe_env() -> dict[str, str]:
    return {"PATH": SAFE_PATH, "LC_ALL": "C.UTF-8", "LANG": "C.UTF-8", "HOME": "/root"}


def invoker() -> tuple[int, int, str, str]:
    raw = os.environ.get("PKEXEC_UID") or os.environ.get("SUDO_UID")
    if not raw or not raw.isdigit():
        raise PermissionError("Unable to identify the authorised desktop user.")
    uid = int(raw)
    if uid == 0:
        raise PermissionError("The broker must be launched by a non-root desktop user.")
    entry = pwd.getpwuid(uid)
    return uid, entry.pw_gid, entry.pw_dir, entry.pw_name


def send(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, separators=(",", ":"), ensure_ascii=False) + "\n")
    sys.stdout.flush()


def child_parent_death_signal() -> None:
    try:
        ctypes.CDLL(None).prctl(1, signal.SIGTERM)
    except Exception:
        pass


def command(argv: list[str], timeout: int = 300, check: bool = False) -> dict[str, Any]:
    if not argv or not re.fullmatch(r"[A-Za-z0-9_.+/-]+", argv[0]):
        raise ValueError("Invalid executable")
    executable = shutil.which(argv[0], path=SAFE_PATH)
    if not executable:
        return {"ok": False, "returncode": 127, "output": f"Not installed: {argv[0]}"}
    argv = [executable, *argv[1:]]
    try:
        proc = subprocess.run(
            argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=timeout, env=safe_env(), check=False,
            preexec_fn=child_parent_death_signal,
        )
        result = {"ok": proc.returncode == 0, "returncode": proc.returncode, "output": proc.stdout or ""}
        if check and proc.returncode:
            raise RuntimeError(result["output"])
        return result
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode(errors="replace")
        return {"ok": False, "returncode": 124, "output": output + f"\nTimed out after {timeout} seconds."}


def write_root_file(path: Path, content: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def enable_unit(unit: str, now: bool = True) -> str:
    args = ["systemctl", "enable"]
    if now:
        args.append("--now")
    args.append(unit)
    return command(args, 90)["output"]


def package_installed(name: str) -> bool:
    return command(["rpm", "-q", name], 20)["ok"]


def install_packages(packages: list[str], progress: Callable[[int, int, str], None] | None = None) -> dict[str, Any]:
    installed: list[str] = []
    failed: list[str] = []
    total = len(packages)
    for index, package in enumerate(packages, 1):
        if progress:
            progress(index - 1, total, f"Checking {package}")
        if package_installed(package):
            installed.append(f"{package} (already installed)")
            continue
        result = command(["dnf", "install", "-y", package], 900)
        if result["ok"]:
            installed.append(package)
        else:
            failed.append(f"{package}: {result['output'][-1000:]}")
    if progress:
        progress(total, total, "Package checks complete")
    return {"installed": installed, "failed": failed, "ok": not failed}


CORE_PACKAGES = [
    "inxi", "smartmontools", "nvme-cli", "lm_sensors", "pciutils", "usbutils",
    "fwupd", "rasdaemon", "edac-utils", "fwts", "kexec-tools", "btrfs-progs",
    "stress-ng", "memtest86+", "iw", "ksystemlog", "gnome-disk-utility",
]
OPTIONAL_ABRT = ["abrt", "abrt-cli", "gnome-abrt"]
COCKPIT_PACKAGES = ["cockpit", "cockpit-system", "cockpit-storaged", "cockpit-pcp", "pcp"]


def setup_capture(uid: int, gid: int, home: str, enable_cockpit: bool, progress) -> dict[str, Any]:
    messages = []
    package_result = install_packages(CORE_PACKAGES + OPTIONAL_ABRT, progress)
    messages.extend(package_result["installed"])

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(LOG_DIR, 0o755)
    Path("/var/log/journal").mkdir(parents=True, exist_ok=True)
    write_root_file(
        Path("/etc/systemd/journald.conf.d/99-fedora-crash-doctor.conf"),
        "[Journal]\nStorage=persistent\nSystemMaxUse=1G\nMaxRetentionSec=30day\nCompress=yes\n",
    )
    command(["systemctl", "restart", "systemd-journald"], 90)
    command(["journalctl", "--flush"], 60)

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    write_root_file(CONFIG_DIR / "owner.json", json.dumps({"uid": uid, "gid": gid, "home": home}, indent=2), 0o600)

    for unit in ("rasdaemon.service", "abrtd.service", "abrt-journal-core.service"):
        if command(["systemctl", "list-unit-files", unit, "--no-legend"], 20)["output"].strip():
            messages.append(enable_unit(unit))

    # Our own services are installed with the application and only enabled here.
    messages.append(enable_unit("fedora-crash-doctor-canary.service"))
    messages.append(enable_unit("fedora-crash-doctor-autoscan.service", now=False))
    command(["systemctl", "--global", "enable", "fedora-crash-doctor-desktop-heartbeat.service"], 60)

    kdump = {"installed": shutil.which("kdumpctl", path=SAFE_PATH) is not None}
    if kdump["installed"]:
        reset = command(["kdumpctl", "reset-crashkernel"], 180)
        command(["systemctl", "enable", "kdump.service"], 60)
        kdump.update({"reset": reset, "status": command(["kdumpctl", "status"], 60)})
    else:
        kdump["status"] = {"ok": False, "output": "kdumpctl is unavailable."}

    cockpit = {"enabled": False}
    if enable_cockpit:
        cockpit_packages = install_packages(COCKPIT_PACKAGES, progress)
        cockpit = cockpit_packages
        cockpit["enabled"] = command(["systemctl", "enable", "--now", "cockpit.socket"], 90)["ok"]

    return {
        "ok": True,
        "packages": package_result,
        "kdump": kdump,
        "cockpit": cockpit,
        "messages": [m for m in messages if m],
        "reboot_required": True,
    }


def unit_state(unit: str) -> dict[str, str]:
    enabled = command(["systemctl", "is-enabled", unit], 20)["output"].strip() or "unknown"
    active = command(["systemctl", "is-active", unit], 20)["output"].strip() or "unknown"
    return {"enabled": enabled, "active": active}


def capture_status() -> dict[str, Any]:
    cmdline = Path("/proc/cmdline").read_text(errors="replace")
    status = {
        "persistent_journal": Path("/var/log/journal").exists(),
        "rasdaemon": unit_state("rasdaemon.service"),
        "abrt": unit_state("abrtd.service"),
        "kdump": unit_state("kdump.service"),
        "canary": unit_state("fedora-crash-doctor-canary.service"),
        "autoscan": unit_state("fedora-crash-doctor-autoscan.service"),
        "cockpit": unit_state("cockpit.socket"),
        "crashkernel_reserved": "crashkernel=" in cmdline,
        "pstore_exposed": Path("/sys/fs/pstore").exists(),
        "canary_log": str(LOG_DIR / "canary.log"),
    }
    score = sum([
        status["persistent_journal"],
        status["rasdaemon"]["enabled"] == "enabled",
        status["canary"]["enabled"] == "enabled",
        status["autoscan"]["enabled"] == "enabled",
        status["crashkernel_reserved"],
    ])
    status["readiness"] = "Ready" if score >= 5 else "Partial" if score >= 2 else "Basic"
    return status


def validate_kdump() -> dict[str, Any]:
    outputs = []
    outputs.append("Current kernel command line:\n" + Path("/proc/cmdline").read_text(errors="replace"))
    for args in (["kdumpctl", "status"], ["kdumpctl", "estimate"], ["systemctl", "status", "kdump.service", "--no-pager"]):
        result = command(list(args), 120)
        outputs.append(f"\n$ {' '.join(args)}\n{result['output']}")
    ready = "crashkernel=" in Path("/proc/cmdline").read_text(errors="replace") and unit_state("kdump.service")["enabled"] == "enabled"
    return {"ok": ready, "ready": ready, "output": "\n".join(outputs), "forced_panic_test_run": False}


def memtest_status() -> dict[str, Any]:
    package = command(["rpm", "-q", "memtest86+"], 20)
    candidates = []
    for root in (Path("/boot"), Path("/boot/efi")):
        if root.exists():
            for path in root.rglob("*memtest*"):
                try:
                    if path.is_file() or path.is_symlink():
                        candidates.append(str(path))
                except OSError:
                    pass
    return {
        "ok": package["ok"] and bool(candidates),
        "package": package["output"].strip(),
        "boot_files": candidates[:60],
        "output": package["output"] + "\n" + "\n".join(candidates),
    }


def smart_short(device: str) -> dict[str, Any]:
    allowed = set(discover_smart_devices())
    if device not in allowed:
        raise ValueError("The requested device is not in smartctl --scan-open.")
    result = command(["smartctl", "-t", "short", device], 60)
    return {"ok": result["ok"], "device": device, "output": result["output"], "note": "The test runs inside the drive. Run a new scan or SMART status after the estimated completion time."}


def btrfs_scrub_start() -> dict[str, Any]:
    fs = command(["findmnt", "-n", "-o", "FSTYPE", "/"], 20)["output"].strip()
    if fs != "btrfs":
        return {"ok": False, "output": f"Root filesystem is {fs or 'unknown'}, not Btrfs."}
    result = command(["btrfs", "scrub", "start", "/"], 120)
    return {"ok": result["ok"], "output": result["output"], "note": "The scrub continues in the background. Run a new scan or btrfs scrub status to review progress."}


def stress_test(kind: str, request_id: str) -> dict[str, Any]:
    if kind == "cpu":
        argv = ["stress-ng", "--cpu", "0", "--timeout", "5m", "--metrics-brief"]
    elif kind == "memory":
        argv = ["stress-ng", "--vm", "2", "--vm-bytes", "60%", "--timeout", "5m", "--metrics-brief"]
    else:
        raise ValueError("Unknown stress test")
    executable = shutil.which(argv[0], path=SAFE_PATH)
    if not executable:
        return {"ok": False, "output": "stress-ng is not installed."}
    proc = subprocess.Popen(
        [executable, *argv[1:]], text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, env=safe_env(), preexec_fn=child_parent_death_signal
    )
    started = time.monotonic()
    while proc.poll() is None:
        elapsed = int(time.monotonic() - started)
        send({"type": "progress", "id": request_id, "current": min(elapsed, 300), "total": 300, "label": f"Running {kind} stress test: {elapsed}s / 300s"})
        time.sleep(2)
    output = proc.stdout.read() if proc.stdout else ""
    return {"ok": proc.returncode == 0, "returncode": proc.returncode, "output": output}


def install_cockpit(progress) -> dict[str, Any]:
    packages = install_packages(COCKPIT_PACKAGES, progress)
    enabled = command(["systemctl", "enable", "--now", "cockpit.socket"], 90)
    return {"ok": packages["ok"] and enabled["ok"], "packages": packages, "service": enabled}


def save_baseline(uid: int, report: dict[str, Any]) -> None:
    directory = STATE_DIR / "baselines" / str(uid)
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    write_root_file(directory / "latest.json", json.dumps(report, ensure_ascii=False), 0o600)


def baseline_path(uid: int) -> str | None:
    path = STATE_DIR / "baselines" / str(uid) / "latest.json"
    return str(path) if path.exists() else None


def install_parent_death_signal() -> None:
    try:
        libc = ctypes.CDLL(None)
        PR_SET_PDEATHSIG = 1
        libc.prctl(PR_SET_PDEATHSIG, signal.SIGTERM)
    except Exception:
        pass


def dispatch(req: dict[str, Any], uid: int, gid: int, home: str, request_id: str) -> Any:
    action = req.get("action")
    params = req.get("params") or {}

    def progress(current: int, total: int, label: str) -> None:
        send({"type": "progress", "id": request_id, "current": current, "total": total, "label": label})

    if action == "scan":
        mode = params.get("mode", "quick")
        if mode not in {"quick", "full"}:
            raise ValueError("Invalid scan mode")
        
        state = req.get("state", {})
        def cancel_requested() -> bool:
            return state.get("cancel_flag", False)

        report = collect(mode, baseline_path(uid), progress, cancel_requested)
        save_baseline(uid, report)
        return report
    if action == "capture_status":
        return capture_status()
    if action == "setup_capture":
        return setup_capture(uid, gid, home, bool(params.get("cockpit", False)), progress)
    if action == "install_tools":
        return install_packages(CORE_PACKAGES + OPTIONAL_ABRT, progress)
    if action == "install_cockpit":
        return install_cockpit(progress)
    if action == "kdump_validate":
        return validate_kdump()
    if action == "memtest_status":
        return memtest_status()
    if action == "smart_short":
        device = str(params.get("device", ""))
        if not re.fullmatch(r"/dev/(?:sd[a-z]+|nvme\d+n\d+|mmcblk\d+)", device):
            raise ValueError("Invalid SMART device")
        return smart_short(device)
    if action == "btrfs_scrub":
        return btrfs_scrub_start()
    if action == "stress_cpu":
        return stress_test("cpu", request_id)
    if action == "stress_memory":
        return stress_test("memory", request_id)
    if action == "list_targets":
        return {"smart_devices": discover_smart_devices(), "root_fstype": command(["findmnt", "-n", "-o", "FSTYPE", "/"], 20)["output"].strip()}
    raise ValueError("Action is not allowed")


import threading

active_tasks = {}

def _dispatch_thread(req: dict[str, Any], uid: int, gid: int, home: str, request_id: str):
    try:
        data = dispatch(req, uid, gid, home, request_id)
        send({"type": "result", "id": request_id, "ok": True, "data": data})
    except Exception as exc:
        send({"type": "result", "id": request_id, "ok": False, "error": f"{type(exc).__name__}: {exc}"})
    finally:
        active_tasks.pop(request_id, None)

def broker() -> int:
    if os.geteuid() != 0:
        print("This helper must be run through pkexec.", file=sys.stderr)
        return 1
    uid, gid, home, username = invoker()
    install_parent_death_signal()
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(STATE_DIR, 0o755)
    send({"type": "ready", "uid": uid, "username": username, "version": app_version()})
    for raw in sys.stdin:
        if len(raw) > MAX_REQUEST:
            send({"type": "error", "id": None, "error": "Request too large"})
            continue
        try:
            req = json.loads(raw)
            if not isinstance(req, dict):
                raise ValueError("Request must be an object")
            
            action = req.get("action")
            if action == "cancel":
                target_id = req.get("target_id")
                task = active_tasks.get(target_id)
                if task:
                    task["cancel_flag"] = True
                continue
                
            request_id = str(req.get("id", ""))[:80]
            if not request_id:
                raise ValueError("Request id required")
                
            state = {"cancel_flag": False}
            req["state"] = state
            active_tasks[request_id] = state
            
            t = threading.Thread(target=_dispatch_thread, args=(req, uid, gid, home, request_id), daemon=True)
            t.start()
        except Exception as exc:
            send({"type": "result", "id": str(locals().get("request_id", "")), "ok": False, "error": f"{type(exc).__name__}: {exc}"})
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] != "broker":
        print("Usage: fedora-crash-doctor-helper broker", file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(broker())
