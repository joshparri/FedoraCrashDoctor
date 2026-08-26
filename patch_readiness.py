import re
with open("collector.py") as f:
    code = f.read()

# Replace tasks in build_tasks
old_tasks = '''        Task("selinux_avc", "SELinux denials this boot", "journalctl -b 0 --no-pager -o short-iso-precise | grep -iE 'avc: +denied|SELinux is preventing' | tail -600", 35, "Software"),
        Task("sysctl_panic", "Panic and lockup settings", ["sysctl", "kernel.panic", "kernel.panic_on_oops", "kernel.softlockup_panic", "kernel.nmi_watchdog", "kernel.hardlockup_panic"], 15, "Software"),
        Task("kdump_service", "Kdump service status", ["systemctl", "is-active", "kdump"], 10, "Software"),
        Task("kdump_package", "Kdump package", ["rpm", "-q", "kexec-tools"], 10, "Software"),
        Task("canary_service", "Canary service status", ["systemctl", "is-active", "fedora-crash-doctor-canary.service"], 10, "Software"),
        Task("journal_dir", "Journal directory", ["ls", "-ld", "/var/log/journal"], 10, "Software"),'''

new_tasks = '''        Task("selinux_avc", "SELinux denials this boot", "journalctl -b 0 --no-pager -o short-iso-precise | grep -iE 'avc: +denied|SELinux is preventing' | tail -600", 35, "Software"),
        Task("sysctl_panic", "Panic and lockup settings", ["sysctl", "kernel.panic", "kernel.panic_on_oops", "kernel.softlockup_panic", "kernel.nmi_watchdog", "kernel.hardlockup_panic"], 15, "Software"),
        Task("kdump_service", "Kdump service status", ["systemctl", "is-active", "kdump"], 10, "Software"),
        Task("kdump_package", "Kdump package", ["rpm", "-q", "kexec-tools"], 10, "Software"),
        Task("canary_service", "Canary service status", ["systemctl", "is-active", "fedora-crash-doctor-canary.service"], 10, "Software"),
        Task("journal_dir", "Journal directory", ["ls", "-ld", "/var/log/journal"], 10, "Software"),
        Task("kexec_loaded", "Crash kernel loaded", ["cat", "/sys/kernel/kexec_crash_loaded"], 10, "Software"),
        Task("crashkernel_mem", "Crash kernel memory reserved", "grep -i crashkernel /proc/cmdline || true", 10, "Software"),
        Task("kdump_target_space", "Kdump target space", "df -h /var/crash || true", 10, "Software"),
        Task("canary_stat", "Canary heartbeat", "stat -c %Y /var/log/fedora-crash-doctor/canary.log || echo 0", 10, "Software"),'''

code = code.replace(old_tasks, new_tasks)

# Replace assess_readiness
old_assess = code[code.find('def assess_readiness'):code.find('def collect(')]

new_assess = '''def assess_readiness(checks: dict[str, Any]) -> dict[str, Any]:
    sources = []
    
    # 1. Journal
    journal_dir_out = checks.get("journal_dir", {}).get("output", "")
    journal_boots_out = checks.get("journal_boots", {}).get("output", "")
    
    if "No such file or directory" in journal_dir_out or checks.get("journal_dir", {}).get("returncode", 1) != 0:
        if len(journal_boots_out.strip().split("\\n")) > 1:
            sources.append({
                "name": "Persistent Journal",
                "status": "unverified",
                "evidence": "Previous boots found but /var/log/journal is missing/unverified.",
                "limitation": "May be using alternative storage.",
                "setup": "Check journald.conf Storage setting.",
                "implications": "Privacy: none. Storage: ~50-200MB. Reboot: required to apply."
            })
        else:
            sources.append({
                "name": "Persistent Journal",
                "status": "volatile_only",
                "evidence": "/var/log/journal is absent and no previous boots are available.",
                "limitation": "Logs are lost upon crash or reboot.",
                "setup": "Run: sudo mkdir -p /var/log/journal && sudo systemd-tmpfiles --create --prefix /var/log/journal && sudo systemctl restart systemd-journald",
                "implications": "Privacy: none. Storage: ~50-200MB. Reboot: required to apply."
            })
    elif checks.get("journal_boots", {}).get("returncode", 0) != 0:
        sources.append({
            "name": "Persistent Journal",
            "status": "error",
            "evidence": "Journal collection returned an error.",
            "limitation": "Cannot determine persistent history availability.",
            "setup": "Check journald service status.",
            "implications": "Privacy: none. Storage: none. Reboot: none."
        })
    elif len(journal_boots_out.strip().split("\\n")) > 1:
        sources.append({
            "name": "Persistent Journal",
            "status": "verified_persistent",
            "evidence": "/var/log/journal exists and previous boots are available.",
            "limitation": "None.",
            "setup": "",
            "implications": ""
        })
    else:
        sources.append({
            "name": "Persistent Journal",
            "status": "unverified",
            "evidence": "/var/log/journal exists but no previous boots are retained.",
            "limitation": "May have just been enabled, or clearing too frequently.",
            "setup": "Wait for next boot to verify persistence, or check MaxRetentionSec.",
            "implications": "Privacy: none. Storage: none. Reboot: none."
        })

    # 2. pstore
    pstore_out = checks.get("pstore", {}).get("output", "")
    if checks.get("pstore", {}).get("returncode", 0) != 0 and "No pstore crash records found" not in pstore_out:
        sources.append({
            "name": "EFI pstore",
            "status": "error",
            "evidence": "Command failed when checking pstore.",
            "limitation": "Cannot verify backend.",
            "setup": "Check dmesg for pstore errors.",
            "implications": "Privacy: none. Storage: none. Reboot: none."
        })
    elif "No such file or directory" in pstore_out:
        sources.append({
            "name": "EFI pstore",
            "status": "unavailable",
            "evidence": "/sys/fs/pstore is not mounted.",
            "limitation": "Firmware does not support pstore or backend missing.",
            "setup": "Ensure EFI variables are accessible or check motherboard settings.",
            "implications": "Privacy: kernel memory only. Storage: minimal. Reboot: N/A."
        })
    elif "No pstore crash records found" in pstore_out:
        # Check backend if possible, but we don't have a direct backend check output unless dmesg has it. 
        # We can assume unverified if empty, since empty doesn't guarantee future capture.
        sources.append({
            "name": "EFI pstore",
            "status": "unverified",
            "evidence": "Directory is present but empty. No backend verified.",
            "limitation": "Empty directory does not guarantee a future crash will be captured.",
            "setup": "None.",
            "implications": "Privacy: kernel memory. Storage: minimal. Reboot: N/A."
        })
    else:
        sources.append({
            "name": "EFI pstore",
            "status": "available_with_records",
            "evidence": "pstore is available and contains previous crash records.",
            "limitation": "May roll over and overwrite older records.",
            "setup": "",
            "implications": ""
        })

    # 3. Kdump
    kdump_pkg = checks.get("kdump_package", {}).get("output", "")
    kdump_svc = checks.get("kdump_service", {}).get("output", "").strip()
    kexec_loaded = checks.get("kexec_loaded", {}).get("output", "").strip()
    crashkernel_mem = checks.get("crashkernel_mem", {}).get("output", "").strip()
    kdump_target = checks.get("kdump_target_space", {}).get("output", "")
    
    if "is not installed" in kdump_pkg or checks.get("kdump_package", {}).get("returncode", 0) != 0:
        sources.append({
            "name": "Kdump Infrastructure",
            "status": "unavailable",
            "evidence": "kexec-tools is not installed.",
            "limitation": "Cannot capture full memory dumps on panic.",
            "setup": "Run: sudo dnf install kexec-tools",
            "implications": "Privacy: captures full memory. Storage: ~100MB-1GB. Reboot: required."
        })
    elif "crashkernel" not in crashkernel_mem:
        sources.append({
            "name": "Kdump Infrastructure",
            "status": "missing_reservation",
            "evidence": "kdump is installed, but crashkernel memory is not reserved.",
            "limitation": "Crash kernel cannot load without reserved memory.",
            "setup": "Configure crashkernel= in grub.",
            "implications": "Privacy: captures full memory. Storage: ~100MB-1GB. Reboot: required."
        })
    elif kexec_loaded != "1":
        sources.append({
            "name": "Kdump Infrastructure",
            "status": "kernel_not_loaded",
            "evidence": "Memory is reserved, but crash kernel is not loaded (kexec_crash_loaded != 1).",
            "limitation": "Kdump service may have failed to start or load the kernel.",
            "setup": "Check systemctl status kdump.",
            "implications": "Privacy: captures full memory. Storage: ~100MB-1GB. Reboot: none."
        })
    elif "No such file or directory" in kdump_target or checks.get("kdump_target_space", {}).get("returncode", 0) != 0:
        sources.append({
            "name": "Kdump Infrastructure",
            "status": "target_missing",
            "evidence": "Kdump target directory (/var/crash) is missing or inaccessible.",
            "limitation": "Dumps have nowhere to be saved.",
            "setup": "Create dump target or verify kdump.conf.",
            "implications": "Privacy: captures full memory. Storage: ~100MB-1GB. Reboot: none."
        })
    elif kdump_svc != "active":
        sources.append({
            "name": "Kdump Infrastructure",
            "status": "misconfigured",
            "evidence": "Kdump is fully configured but the service is inactive.",
            "limitation": "Cannot capture full memory dumps on panic.",
            "setup": "Run: sudo systemctl enable --now kdump",
            "implications": "Privacy: captures full memory. Storage: ~100MB-1GB. Reboot: none."
        })
    else:
        sources.append({
            "name": "Kdump Infrastructure",
            "status": "verified_ready",
            "evidence": "Kdump is active, crashkernel reserved, kernel loaded, and target available.",
            "limitation": "May not capture power loss or hard hardware lockups.",
            "setup": "",
            "implications": ""
        })

    # 4. Sysctls
    sysctl_out = checks.get("sysctl_panic", {}).get("output", "")
    ready_sysctls = []
    unready_sysctls = []
    
    triggers = {
        "kernel.panic": ("panic", "Reboots automatically N seconds after any panic."),
        "kernel.panic_on_oops": ("panic_on_oops", "Causes a panic when a kernel oops occurs."),
        "kernel.softlockup_panic": ("softlockup_panic", "Causes a panic on CPU soft lockup (e.g. infinite loop in kernel)."),
        "kernel.hardlockup_panic": ("hardlockup_panic", "Causes a panic on CPU hard lockup (interrupts disabled)."),
        "kernel.nmi_watchdog": ("nmi_watchdog", "Enables NMI watchdog for hardware-level lockup detection.")
    }
    
    for key, (name, explanation) in triggers.items():
        if key == "kernel.panic":
            if f"{key} = 0" in sysctl_out:
                unready_sysctls.append(name)
            elif f"{key} =" in sysctl_out:
                ready_sysctls.append(name)
        else:
            if f"{key} = 1" in sysctl_out:
                ready_sysctls.append(name)
            else:
                unready_sysctls.append(name)

    if not unready_sysctls:
        sources.append({
            "name": "Kernel Panic Settings",
            "status": "ready",
            "evidence": "All recommended panic triggers are enabled.",
            "limitation": "Does not help with user-space or hardware/GPU freezes that don't trigger the watchdog.",
            "setup": "",
            "implications": ""
        })
    else:
        sources.append({
            "name": "Kernel Panic Settings",
            "status": "disabled_intentionally",
            "evidence": f"Disabled panic triggers: {', '.join(unready_sysctls)}.",
            "limitation": "Deliberately disabled for safety policy. Does not guarantee evidence capture if enabled. Helps mostly with kernel-level lockups.",
            "setup": "If desired, set via /etc/sysctl.d/99-crash-capture.conf and run sudo sysctl --system.",
            "implications": "Privacy: none. Storage: none. Reboot: automatic reboots on panic. Risk of work or data loss on forced panic. Kdump must be verified first."
        })

    # 5. Canary
    canary_svc = checks.get("canary_service", {}).get("output", "").strip()
    canary_stat = checks.get("canary_stat", {}).get("output", "").strip()
    import time
    
    if canary_svc != "active":
        sources.append({
            "name": "System Canary",
            "status": "unavailable",
            "evidence": "Service is inactive.",
            "limitation": "No pre-crash telemetry recorded.",
            "setup": "Run: sudo systemctl enable --now fedora-crash-doctor-canary.service",
            "implications": "Privacy: none. Storage: minimal. Reboot: N/A."
        })
    else:
        try:
            mtime = int(canary_stat)
            age = time.time() - mtime
            if age > 120:
                sources.append({
                    "name": "System Canary",
                    "status": "stale",
                    "evidence": f"Service active, but heartbeat is stale ({int(age)}s old).",
                    "limitation": "May be failing to write or location is unwritable.",
                    "setup": "Check canary service logs.",
                    "implications": "Privacy: none. Storage: minimal. Reboot: N/A."
                })
            else:
                sources.append({
                    "name": "System Canary",
                    "status": "verified_active",
                    "evidence": "Service is active and heartbeat is recent.",
                    "limitation": "Relies on system not fully locking up immediately.",
                    "setup": "",
                    "implications": ""
                })
        except ValueError:
            sources.append({
                "name": "System Canary",
                "status": "unavailable",
                "evidence": "Service active, but canary log file is missing or inaccessible.",
                "limitation": "Cannot write telemetry.",
                "setup": "Ensure /var/log/fedora-crash-doctor is writable.",
                "implications": "Privacy: none. Storage: minimal. Reboot: N/A."
            })

    # Recommend next step safely
    recommendation = "Capture mechanisms are fully prepared."
    
    if next((s for s in sources if s["name"] == "Persistent Journal" and s["status"] in ("volatile_only", "error", "unavailable")), None):
        recommendation = "Missing Infrastructure: Enable Persistent Journal to prevent log loss."
    elif next((s for s in sources if s["name"] == "System Canary" and s["status"] in ("unavailable", "stale")), None):
        recommendation = "Missing Infrastructure: Enable System Canary for pre-crash telemetry."
    elif next((s for s in sources if s["name"] == "Kdump Infrastructure" and s["status"] in ("unavailable", "misconfigured", "target_missing", "missing_reservation", "kernel_not_loaded")), None):
        recommendation = "Verification Gap: Fix Kdump Infrastructure (see setup instructions)."
    elif next((s for s in sources if s["name"] == "Persistent Journal" and s["status"] == "unverified"), None):
        recommendation = "Verification Gap: Monitor Journal across reboots to verify persistence."
    elif next((s for s in sources if s["name"] == "Kernel Panic Settings" and s["status"] != "ready"), None):
        recommendation = "Optional Higher-Risk: Enable Panic Settings (ONLY if kdump is fully verified)."

    return {
        "sources": sources,
        "recommendation": recommendation
    }
'''

code = code.replace(old_assess, new_assess)
with open("collector.py", "w") as f:
    f.write(code)
