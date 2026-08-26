# Fedora Crash Doctor Host Stability Audit

Generated: 2026-08-26T11:34:46+10:00

## Host

- Hostname: `AVANCE-WS7`
- Kernel: `7.1.9-200.fc44.x86_64`
- Relevant kernel args: `i915.enable_psr=0 i915.enable_dc=0 crashkernel=2G-64G:256M,64G-:512M`

## Findings

### Stable Fedora kernel update is available

- Category: `updates`
- Classification: `high-confidence preventative fix`
- Evidence:
  - `Running kernel: 7.1.9-200.fc44.x86_64`
  - `Updating and loading repositories:`
  - ` Fedora 44 - x86_64 - Updates           100% |  13.5 KiB/s |  55.8 KiB |  00m04s`
  - `>>> Curl error (56): Failure when receiving data from the peer for https://mirrors.fedoraproject.org/metalink?repo=updates-released-f44&arch=x86_64 [Recv failure: Connection reset by peer] - https://mirrors.fedoraproject.org/metalink?repo=updates-released-f44&arch=x86_64`
  - ` google-chrome                          100% |   3.7 KiB/s |   1.3 KiB |  00m00s`
  - ` Fedora 44 openh264 (From Cisco) - x86_ 100% | 513.0   B/s | 986.0   B |  00m02s`
  - ` Fedora 44 - x86_64                     100% |  40.9 KiB/s |  50.1 KiB |  00m01s`
  - ` Docker CE Stable - x86_64              100% |   5.5 KiB/s |   2.0 KiB |  00m00s`
  - ` Visual Studio Code                     100% |   4.3 KiB/s |   1.5 KiB |  00m00s`
- Recommended action:
  - Run sudo dnf upgrade --refresh from stable repositories, then reboot into the newest kernel.

### systemd-oomd is active

- Category: `memory`
- Classification: `partial protection`
- Evidence:
  - `systemd-oomd active=active enabled=enabled`
  - `oomctl` shows Memory Pressure Monitored CGroups for `user@1002.service` and `app.slice` with an 80% limit for 20s.
  - `oomctl` shows **Swap Monitored CGroups** is completely empty.
- Recommended action:
  - systemd-oomd is active but may not fully protect the desktop during extreme swap thrashing because ManagedOOMSwap is not effectively monitoring any cgroups, and the 80% memory pressure limit over 20s may be too lenient. Keep enabled, but monitor if it intervenes in time during the next freeze.

### zram swap is present

- Category: `memory`
- Classification: `confirmed protection`
- Evidence:
  - `NAME       TYPE            SIZE      USED PRIO
/dev/zram0 partition 8589930496 500383744  100`
  - `NAME         DISKSIZE      DATA     COMPR ALGORITHM STREAMS ZERO-PAGES     TOTAL MEM-LIMIT  MEM-USED MIGRATED COMP-RATIO MOUNTPOINT
/dev/zram0 8589934592 480456704 159033888 lzo-rle                  377 172101632         0 194064384        0     2.7917 [SWAP]`
- Recommended action:
  - Monitor pressure and process growth before changing zram size. Current priority/usage should be captured after any future freeze.

### Current boot has Intel i915 atomic update failures

- Category: `graphics`
- Classification: `confirmed problem`
- Evidence:
  - `Aug 26 10:35:14 AVANCE-WS7 kernel: i915 0000:00:02.0: [drm] *ERROR* Atomic update failure on pipe B (start=522178 end=522179) time 173 us, min 1073, max 1079, scanline start 1069, end 1081`
  - `Aug 26 11:11:07 AVANCE-WS7 kernel: i915 0000:00:02.0: [drm] *ERROR* Atomic update failure on pipe B (start=651348 end=651349) time 164 us, min 1073, max 1079, scanline start 1071, end 1082`
  - `Aug 26 11:17:08 AVANCE-WS7 kernel: i915 0000:00:02.0: [drm] *ERROR* Atomic update failure on pipe B (start=673003 end=673004) time 192 us, min 1073, max 1079, scanline start 1069, end 1082`
  - `Aug 26 11:17:08 AVANCE-WS7 kernel: i915 0000:00:02.0: [drm] *ERROR* Atomic update failure on pipe B (start=673012 end=673013) time 193 us, min 1073, max 1079, scanline start 1069, end 1082`
  - `Aug 26 11:17:08 AVANCE-WS7 kernel: i915 0000:00:02.0: [drm] *ERROR* Atomic update failure on pipe B (start=673036 end=673037) time 187 us, min 1073, max 1079, scanline start 1069, end 1081`
- Recommended action:
  - Keep Chrome/VS Code GPU acceleration disabled, update kernel/Mesa/Plasma from stable repos, and run a one-monitor Wayland A/B test.

### Correctable PCIe/AER messages observed

- Category: `pcie`
- Classification: `monitoring only`
- Evidence:
  - `Aug 26 08:10:09 AVANCE-WS7 kernel: acpi PNP0A08:00: _OSC: OS now controls [PCIeHotplug SHPCHotplug PME AER PCIeCapability LTR DPC]`
  - `Aug 26 08:10:09 AVANCE-WS7 kernel: pcieport 0000:00:1b.0: AER: enabled with IRQ 120`
  - `Aug 26 08:10:09 AVANCE-WS7 kernel: pcieport 0000:00:1c.0: AER: enabled with IRQ 121`
  - `Aug 26 10:29:34 AVANCE-WS7 kernel: pcieport 0000:00:1c.0: AER: Multiple Correctable error message received from 0000:02:00.0`
  - `Aug 26 10:29:34 AVANCE-WS7 kernel: rtw88_8821ce 0000:02:00.0: PCIe Bus Error: severity=Correctable, type=Data Link Layer, (Receiver ID)`
  - `Aug 26 11:13:20 AVANCE-WS7 kernel: pcieport 0000:00:1c.0: AER: Multiple Correctable error message received from 0000:02:00.0`
  - `Aug 26 11:13:20 AVANCE-WS7 kernel: rtw88_8821ce 0000:02:00.0: PCIe Bus Error: severity=Correctable, type=Data Link Layer, (Receiver ID)`
- Recommended action:
  - Keep correlating timestamps. Do not add pci=noaer or disable ASPM unless uncorrectable errors or freeze-time correlation appears.

### USB/storage messages exist in the kernel log

- Category: `storage`
- Classification: `monitoring only`
- Evidence:
  - `Aug 26 08:10:09 AVANCE-WS7 kernel: usb 1-14: Manufacturer: Realtek `
  - `Aug 26 08:10:09 AVANCE-WS7 kernel: usb 1-14: SerialNumber: 00e04c000001`
  - `Aug 26 08:10:13 AVANCE-WS7 kernel: usbcore: registered new interface driver btusb`
  - `Aug 26 08:10:13 AVANCE-WS7 kernel: usbcore: registered new interface driver snd-usb-audio`
  - `Aug 26 08:10:13 AVANCE-WS7 kernel: EXT4-fs (nvme0n1p2): mounted filesystem 70877dfc-0005-4fa3-b003-48e64e667caa r/w with ordered data mode. Quota mode: none.`
  - `Aug 26 08:13:01 AVANCE-WS7 kernel: squashfs: version 4.0 (2009/01/31) Phillip Lougher`
  - `Aug 26 10:20:11 AVANCE-WS7 kernel: CIFS: Attempting to mount //10.245.173.126/C$/Users/Josh/AppData/Local/pnpm/store/v11/projects/1b9c76b76253915e072f83ad2cf58dcb/node_modules/.pnpm/next@14.2.35_@playwright+test@1.61.1_react-dom@18.3.1_react@18.3.1__react@18.3.1/node_modules/busboy`
  - `Aug 26 10:42:30 AVANCE-WS7 kernel: CIFS: Attempting to mount //10.245.173.126/C$/Users/Josh/AppData/Local/pnpm/store/v11/projects/6ccbcf18a2cc5ab826d0246d2773483a/node_modules/.pnpm/node_modules/busboy`
- Recommended action:
  - Attribute errors to physical devices by VID:PID/path before blaming the internal NVMe. Replace/test cables/enclosures for recurring external-drive errors.

### Crash capture infrastructure is active

- Category: `capture`
- Classification: `confirmed protection`
- Evidence:
  - `canary active=active enabled=enabled`
  - `autoscan active=inactive enabled=enabled`
  - `kdump active=active enabled=enabled`
  - `kexec_crash_loaded=1`
  - `persistent journal directory exists`
- Recommended action:
  - Keep these enabled. After any freeze, prefer TTY recovery and run Crash Doctor before making unrelated changes.

## Not Supported By Current Evidence

- Internal NVMe failure is not the leading explanation unless SMART/NVMe/Btrfs errors correlate with freezes.
- General Fedora/RPM corruption is not supported by the current health checks.
- Realtek Wi-Fi/PCIe correctable errors should not be treated as causal without timing correlation.
- Global UAS/ASPM/i915 kernel parameters should not be added speculatively.

### Post-Stabilization (v1.0) Maintenance Check
- Category: `maintenance`
- Classification: `verified healthy`
- Evidence:
  - Btrfs scrub reports `0` errors across all error types.
  - Internal NVMe SMART reports `0` media errors, `30%` used, and `0` critical warnings.
  - kdump and persistent journal are active and operational.
- Recommended action:
  - Continue normal operation. The internal storage is healthy and properly configured. USB-based I/O errors are confirmed to be external device faults.
