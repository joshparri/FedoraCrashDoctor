# Fedora / Linux Crash & Freeze Master Record

## 1. The overall diagnosis

Across all the incidents, I’d currently rank the causes like this:

| Rank | Problem                                                       |                             Confidence |                              Importance |
| ---- | ------------------------------------------------------------- | -------------------------------------: | --------------------------------------: |
| 🥇   | **Intel i915 + KWin/Wayland + multi-monitor display freezes** |                              Very high |                                Critical |
| 🥈   | **RAM + zram/swap exhaustion → extreme I/O pressure**         |                              Very high |                                Critical |
| 🥉   | **USB storage/enclosure disconnects and I/O errors**          |                                   High |                             Significant |
| 4    | Plasma shell/panel itself freezing                            |                                   High |                                Moderate |
| 5    | Chrome/VS Code GPU acceleration aggravating graphics problems |                                   High |                             Significant |
| 6    | Discover / PackageKit / Flatpak metadata problems             |                                   High |               Annoying, not crash cause |
| 7    | Realtek RTL8821CE PCIe/AER warnings                           | Medium evidence, low causal confidence |                     Probably incidental |
| 8    | Internal NVMe failure                                         |                         Low confidence | **Not currently supported by evidence** |
| 9    | General Fedora/package corruption                             |                         Low confidence |           **Not supported by evidence** |

The important distinction is that **some “computer freezes” were not actually kernel freezes**. Linux itself was still running; KDE/Wayland/KWin had stopped giving you a usable graphical desktop.

---

# CHRONOLOGY

## July 8 — major KDE/Wayland display freeze

### What happened

You were running Fedora KDE Plasma/Wayland with multiple monitors.

Evidence included:

* `kwin_wayland` becoming unresponsive
* Intel `i915` graphics errors
* `Atomic update failure on pipe A`
* `Atomic update failure on pipe B`
* Chrome Wayland/GPU errors
* VS Code becoming unresponsive
* Plasma appearing completely frozen

The crucial clue:

**Ctrl+Alt+F3 still opened a TTY.**

That means:

> kernel → alive
> Linux → alive
> systemd → alive
> graphics session → broken

### Likely chain

**Intel integrated GPU**
↓
**i915 DRM driver**
↓
multi-monitor atomic display update
↓
**KWin Wayland compositor stalls**
↓
Chrome / VS Code GPU clients become stuck
↓
Plasma appears frozen

### Emergency recovery

Try:

```bash
Ctrl+Alt+F3
```

Log in.

Then:

```bash
pkill -f google-chrome
pkill -f code
```

Try returning:

```text
Ctrl+Alt+F2
```

If the graphical session remains dead:

```bash
sudo systemctl reboot
```

This is much better than holding the power button because the system gets an orderly shutdown.

---

# July 29 — another display-stack crash / unclean reboot

Crash evidence later showed:

```text
i915 ... Atomic update failure on pipe A
i915 ... Atomic update failure on pipe B
```

and after reboot:

```text
system.journal corrupted or uncleanly shut down,
renaming and replacing
```

Fedora Crash Doctor ultimately classified the evidence around this period as:

**Display-stack freeze**

rather than proof of a kernel panic.

Again, this strengthens the i915/KWin hypothesis.

---

# July 29–30 — basic Fedora health checks

Your machine was:

```text
Fedora 44
kernel 7.1.5-200.fc44.x86_64
```

Checks included:

```bash
systemctl --failed --no-pager
sudo dnf check
```

Result:

```text
0 loaded units listed
```

and no significant DNF consistency problem.

You also ran Fedora updates and firmware checks.

There were **no applicable firmware updates**.

### Conclusion

This argued strongly against:

* broken Fedora installation
* large-scale RPM corruption
* failed system services
* outdated device firmware being the obvious root cause

---

# July 30 — VS Code GPU workaround

Because Electron/Chromium applications were involved in the graphics freezes, we disabled VS Code hardware acceleration.

You tested:

```bash
code --disable-gpu
```

Then changed:

```text
~/.config/Code/argv.json
```

to contain:

```json
{
    "disable-hardware-acceleration": true
}
```

and removed the old GPU cache:

```bash
rm -rf ~/.config/Code/GPUCache
```

This remains a sensible workaround.

---

# Chrome GPU acceleration

Chrome was another recurring participant in the display-stack incidents.

By August 26 your Chrome processes were running with GPU functionality disabled, including flags corresponding to:

```text
--disable-gpu-compositing
--use-gl=disabled
```

For this particular PC I think **keeping browser hardware acceleration disabled for now is reasonable**.

It removes one variable from the i915/KWin problem.

---

# Fedora Crash Doctor begins

Around July 30 we turned the recurring Fedora crashes into a proper project:

```text
/home/josh/Downloads/troulbeshoot/fedora-crash-doctor
```

It evolved from a diagnostic script into a substantial crash-analysis tool.

It eventually gained:

* PySide6 GUI
* CLI scanner
* privileged PolicyKit broker
* read-only collector
* systemd integration
* crash capture
* persistent logging
* evidence ranking
* RPM packaging
* automated tests
* kdump checking
* pstore checking
* SELinux AVC detection
* OOM detection
* zram/memory analysis
* GPU/i915 analysis
* Intel `xe` detection
* KWin/Wayland analysis
* filesystem/storage diagnostics
* NVMe SMART
* regular SMART
* Btrfs device statistics
* PCIe errors
* systemd service failures
* coredumps
* pressure-stall information
* boot comparison
* desktop heartbeat
* canary monitoring

This became considerably more useful than simply searching `journalctl` manually.

---

# August 4–5 — Crash Doctor discovers several historical problems

A real scan uncovered four categories.

## A. Historical Chrome OOM events

Chrome had previously been killed because of memory exhaustion.

At first this was just historical evidence and **wasn't enough to prove that Chrome had crashed Fedora**.

That distinction became important later.

---

# B. Intel i915 errors

Crash Doctor detected:

```text
i915 ... [drm] *ERROR* Atomic update failure on pipe A
```

This reinforced our existing graphics-stack hypothesis.

---

# C. Realtek RTL8821CE PCIe errors

Crash Doctor found correctable PCIe/AER errors associated with:

**Realtek RTL8821CE Wi-Fi**

These were noteworthy but did **not correlate convincingly with the freezes**.

We specifically decided not to start throwing kernel parameters like:

```text
pci=noaer
```

at the system.

That remains the right decision.

AER warnings can be symptoms rather than root causes.

---

# D. USB storage error

Crash Doctor found:

```text
Buffer I/O error
lost async page write
```

on `/dev/sda1`.

Investigation identified that device as a:

**SanDisk Cruzer Blade 16 GB USB drive**

and the error corresponded to its disconnection.

The internal NVMe wasn't implicated in this particular incident.

---

# August 5 — storage health

Crash Doctor grew support for:

```bash
smartctl
nvme smart-log
btrfs device stats
lsblk
journalctl
```

The internal Toshiba NVMe was not giving us convincing evidence of a storage failure.

At one stage SMART reported:

```text
PASSED
```

and the drive temperature was around:

```text
23°C
```

The drive had accumulated unsafe shutdown/error counters, but those counters by themselves didn't establish it as the cause of the freezes.

### My current conclusion

**Do not replace the internal NVMe merely because Fedora froze.**

The strongest evidence lies elsewhere.

---

# August 5 — Fedora Crash Doctor capture system

We improved the ability to catch crashes rather than reconstruct them afterwards.

Crash Doctor began checking:

### Persistent journal

So the previous boot survives:

```bash
journalctl -b -1
```

### kdump

Including:

```bash
systemctl is-active kdump
rpm -q kexec-tools
cat /sys/kernel/kexec_crash_loaded
```

### Kernel command line

Looking for:

```text
crashkernel=
```

### pstore

For firmware/kernel crash data.

### SELinux

For AVC denials.

### `/var/crash`

To ensure crash dump storage existed and had sufficient capacity.

### Canary

Service:

```text
fedora-crash-doctor-canary.service
```

Log:

```text
/var/log/fedora-crash-doctor/canary.log
```

### Desktop heartbeat

This helps distinguish:

**entire operating system stopped**

from:

**desktop stopped while Linux continued running**.

That distinction is enormously useful for your particular problem.

---

# August 5 — capture readiness

Eventually Crash Doctor reported roughly:

```text
persistent journal: verified_persistent
kdump: verified_ready
canary: verified_active
EFI pstore: unverified
panic triggers: disabled_intentionally
```

There were:

```text
44/44 analysis tests
1/1 headless GUI test
```

passing during one of the mature builds.

This means the crash instrumentation became quite solid.

---

# August 14 — probably the most important discovery after i915

This freeze was different.

Telemetry showed:

```text
swap: 8191 / 8191 MB
```

**100% full.**

Available RAM collapsed from roughly:

```text
1.3 GB
```

to:

```text
475 MB
```

I/O pressure rose from effectively zero to approximately:

```text
85.27%
```

and system load climbed from around:

```text
4.9
```

to:

```text
33
```

Then KWin reported that its main thread had been hanging.

This was exceptionally strong evidence of:

# memory exhaustion → swapping/thrashing → desktop starvation

rather than primarily an i915 crash.

My confidence at the time was around **90%**.

---

# Why full zram/swap can make Fedora look dead

Once RAM fills:

```text
RAM full
↓
zram/swap fills
↓
kernel aggressively reclaims memory
↓
applications repeatedly fault pages in/out
↓
CPU + I/O pressure explodes
↓
desktop can't schedule work quickly enough
↓
KWin stops painting
↓
mouse / taskbar / windows appear frozen
```

The kernel may still technically be alive.

That fits what we observed.

---

# Best memory-freeze diagnosis

During slowdown, immediately run:

```bash
free -h
```

then:

```bash
swapon --show
```

and:

```bash
zramctl
```

then find memory hogs:

```bash
ps -eo pid,user,comm,rss,%mem --sort=-rss | head -30
```

and:

```bash
systemd-cgtop
```

Also useful:

```bash
cat /proc/pressure/memory
cat /proc/pressure/io
```

If `full avg10` or `some avg10` shoots upwards while swap is full, we're seeing the same failure again.

---

# Best immediate fix when memory pressure begins

Don't wait until Plasma completely freezes.

Close the largest offender.

Chrome is an obvious candidate when it has hundreds of processes/tabs/extensions active.

Check:

```bash
ps -eo pid,comm,rss --sort=-rss | head -20
```

If Chrome is clearly consuming enormous memory:

```bash
pkill -f chrome
```

only if you're happy to terminate the browser session.

The goal isn't simply to add enormous amounts of swap.

**A runaway memory consumer needs identifying.**

That was why we subsequently upgraded Crash Doctor to record process-level RAM and swap behaviour.

---

# August 14 — another USB filesystem problem

Shortly before the memory-pressure freeze, an external storage device disconnected.

We saw:

* EXT4 errors
* JBD2 errors
* USB disconnection
* `/dev/sda8`

The timing wasn't enough to establish it as the primary freeze cause because the subsequent memory-pressure evidence was much stronger.

But this gives us another rule:

# Never trust a flaky USB enclosure/cable/drive with a mounted filesystem.

---

# External 256 GB disk / Realtek enclosure problem

At another point `/dev/sda` was a **256 GB disk attached through a Realtek USB storage bridge**.

The enclosure/device repeatedly behaved badly.

A raw read:

```bash
sudo dd if=/dev/sda of=/dev/null bs=16M iflag=direct status=progress
```

made it to about:

```text
3.4 GB
```

before:

```text
Input/output error
```

The kernel also logged USB disconnect/reconnect behaviour.

SMART through the bridge could still say:

```text
PASSED
```

That does **not** rule out:

* bad USB cable
* bridge controller instability
* insufficient USB power
* UAS compatibility problem
* enclosure fault
* intermittent physical connection

### Best solution

In order:

1. Different USB port.
2. Different known-good cable.
3. Different enclosure/adapter.
4. Direct SATA/NVMe attachment where possible.
5. Examine:

```bash
journalctl -k -f
```

while reading the drive.

If we repeatedly see UAS resets, then consider a device-specific UAS quirk — **but only after identifying the enclosure's exact USB VID:PID**.

I would still **not disable UAS globally**.

---

# August 24 — ddrescue / Fedora clone

You used a Fedora live environment to clone the Fedora NVMe onto another SSD.

`ddrescue` got to approximately:

```text
181,648 MB rescued
70.93%
~73.6 MB/s
```

with only a few minutes remaining at the point we checked it.

The important lesson from the USB problems above is:

**ddrescue is the right tool for questionable source/destination I/O.**

It is much safer than repeatedly using raw `dd` against unstable storage because it maintains a rescue map and can resume.

---

# August 24 — Fedora Crash Doctor used as the repair authority

You specifically wanted troubleshooting driven by Fedora Crash Doctor rather than randomly changing ForgeGrid or unrelated software.

We examined:

```text
fedora_crash_doctor.py
collector.py
setup_capture.sh
canary.py
patch_readiness.py
desktop_heartbeat.py
```

and ran things including:

```bash
python3 canary.py
python3 -m unittest discover -v
python3 collector.py --output scan.json
python3 fedora_crash_doctor.py --cli --scan
```

Later:

```bash
python3 patch_readiness.py
```

and:

```bash
sudo ./setup_capture.sh
```

The work concentrated on:

* kernel/graphics state
* crash capture
* persistent evidence
* kdump
* canary
* desktop heartbeat

This is exactly the direction I would continue.

---

# August 25–26 — KDE Discover permanently saying/fetching updates

This was **not a system freeze**, but another Fedora issue we've worked through.

Discover logged things including:

```text
PreparedUpgrade
```

broken/missing:

```text
fedora-testing
```

Flatpak AppStream metadata, QSslSocket warnings, portal registration errors and empty sources.

We tried:

```bash
sudo dnf clean all
sudo dnf makecache --refresh
sudo systemctl restart packagekit
flatpak update --appstream
```

and:

```bash
sudo flatpak repair
```

then:

```bash
pkcon refresh force
```

which completed successfully.

We removed the problematic Flatpak remote:

```bash
sudo flatpak remote-delete fedora-testing
```

and afterwards the system remote list showed just the Fedora OCI source.

We also cleared Discover's cache:

```bash
rm -rf ~/.cache/discover
killall plasma-discover
plasma-discover
```

### Best approach

If Discover itself is misbehaving, don't confuse that with Fedora being unhealthy.

Use:

```bash
sudo dnf upgrade --refresh
```

for RPM packages and:

```bash
flatpak update
```

for Flatpaks.

If those succeed, Fedora's package system is fundamentally functioning even if Discover's GUI is unhappy.

---

# August 26 — current Plasma panel/taskbar freeze

Today you've also been investigating the KDE bar/panel freezing.

You ran:

```bash
kscreen-doctor -o
```

and the display configuration showed outputs including `DP-2`, connected/enabled, running at 1920×1080.

Given the history, there are three levels here.

## Level 1 — only panel/taskbar frozen

Try:

```bash
plasmashell --replace
```

Or where the systemd Plasma service is actually active:

```bash
systemctl --user restart plasma-plasmashell.service
```

`plasmashell --replace` remains a useful fallback because Fedora's exact Plasma systemd-session behaviour varies.

---

## Level 2 — Plasma frozen but terminal still works

Go to TTY:

```text
Ctrl+Alt+F3
```

Check:

```bash
ps aux | grep -E 'kwin|plasmashell'
```

and:

```bash
journalctl --user -b -p warning
```

plus:

```bash
journalctl -k -b | grep -iE 'i915|drm|gpu|hang|reset'
```

If the kernel output contains another:

```text
Atomic update failure
```

we have very strong evidence this is another graphics-stack event rather than simply a broken panel.

---

## Level 3 — full graphical session dead

From TTY, perform an orderly reboot:

```bash
sudo systemctl reboot
```

Then investigate the previous boot rather than guessing:

```bash
journalctl -b -1 -p warning
```

and:

```bash
journalctl -k -b -1 | grep -iE \
'i915|drm|gpu|hang|reset|oom|out of memory|blocked|nvme|usb|uas|ext4|btrfs'
```

---

# X11 as an A/B test

Back in July we tried to install:

```bash
sudo dnf install plasma-workspace-x11
```

but received repeated Fedora mirror `404` errors for a specific RPM.

That was a repository/version synchronisation problem at the time rather than proof the package didn't exist.

As of **26 August 2026**, Fedora 44 does currently have:

```text
plasma-workspace-x11 6.7.4-1.fc44
```

available.

However, this needs an important qualification.

Fedora KDE officially moved to **Wayland-only support** with Plasma 6. The Fedora KDE SIG does not officially support the legacy X11 session. The Fedora 44 X11 package is maintained independently.

Therefore I would use X11 only as a **diagnostic A/B experiment**:

```bash
sudo dnf install plasma-workspace-x11
```

Login to:

```text
Plasma (X11)
```

and use it for a few days.

### Interpretation

If:

**Wayland freezes + X11 doesn't**

that is extremely strong evidence against hardware/storage and towards:

**KWin Wayland / DRM / i915 / multi-monitor stack.**

I would not necessarily make X11 your permanent future desktop.

---

# The multi-monitor factor

Your display setup keeps showing up in this story.

You've used KDE across two monitors, moved Plasma panels between displays, and the actual GPU errors concern DRM atomic display updates.

That combination matters.

A useful controlled test would therefore be:

### Test A

Wayland + two monitors.

### Test B

Wayland + one monitor.

### Test C

X11 + two monitors.

If only A fails, we've dramatically narrowed the problem.

---

# KDE panel configuration itself

You've also changed the panel layout:

* panel originally on right-hand side of left monitor
* removed/recreated panel
* moved panel to bottom of right monitor

This creates another possibility for **panel-only freezes**:

broken/stale Plasma configuration.

Do not immediately wipe all KDE configuration.

First restart Plasma.

If one specific panel repeatedly breaks while KWin remains healthy, then we can isolate Plasma's panel configuration rather than rebuilding your entire desktop.

---

# Realtek Wi-Fi / PCIe errors

Crash Doctor found:

```text
RTL8821CE
```

PCIe correctable errors.

So far there is **not enough evidence** that they cause the freezes.

Best approach:

```bash
journalctl -k -b | grep -iE 'aer|pcie|rtl8821'
```

Compare timestamps against the actual freeze.

Don't blindly use:

```text
pci=noaer
```

and don't globally disable PCIe ASPM unless Crash Doctor demonstrates a correlation.

Suppressing an error message is not the same thing as fixing a fault.

---

# Internal NVMe

We've repeatedly looked for:

* SMART failures
* NVMe errors
* Btrfs problems
* I/O errors

The internal drive has **not emerged as the leading explanation**.

Therefore:

### Do

Continue monitoring:

```bash
sudo nvme smart-log /dev/nvme0
```

and:

```bash
sudo btrfs device stats /
```

where applicable.

### Don't

Replace the SSD purely because KDE freezes.

---

# System journal corruption after forced shutdowns

We saw:

```text
system.journal corrupted or uncleanly shut down
```

This is generally a consequence of hard power-offs.

That's another reason the TTY recovery route matters.

Instead of holding the power button:

```text
Ctrl+Alt+F3
```

then:

```bash
sudo reboot
```

Persistent journalling also gives Crash Doctor much better evidence afterwards.

---

# Firmware

We checked with:

```bash
sudo fwupdmgr refresh --force
sudo fwupdmgr get-updates
sudo fwupdmgr update
```

and there weren't outstanding updates for the affected hardware at the time.

There was also a UEFI/dbx unsupported-style fwupd message at one point.

That isn't currently a convincing freeze cause.

---

# Fedora package integrity

We've run combinations of:

```bash
dnf check
dnf repolist
dnf history list
```

with no evidence that package-database corruption explains the crashes.

Again:

**Fedora itself does not appear generally corrupted.**

---

# Old Ubuntu issue — 2015

The oldest Linux troubleshooting I can retrieve predates all of this.

On Ubuntu 14.04 on an Asus N53JQ:

* Firefox 35
* Chromium 40
* Sylpheed
* Linux 3.13
* TP-Link Wi-Fi / `ath9k`

were involved in a situation where university email access timed out despite the Wi-Fi appearing connected.

I don't have a recorded confirmed resolution.

It's unrelated to the current Fedora crash family.

---

# THE MASTER RECOVERY PROCEDURE

When Fedora appears frozen, **don't reboot immediately.**

## Step 1 — test whether Linux is alive

Press:

```text
Ctrl+Alt+F3
```

### If TTY works

The kernel probably hasn't frozen.

Immediately collect:

```bash
date
free -h
swapon --show
cat /proc/pressure/memory
cat /proc/pressure/io
```

Then:

```bash
journalctl -k -b --since "-10 min" | tail -200
```

Then:

```bash
journalctl --user -b --since "-10 min" | tail -200
```

And:

```bash
ps -eo pid,user,comm,rss,%mem --sort=-rss | head -30
```

That one snapshot could tell us whether this is:

**GPU**

or:

**memory pressure**

almost immediately.

---

# Step 2 — classify it

## i915 / DRM errors present

Example:

```text
Atomic update failure
GPU HANG
reset
```

→ graphics problem.

## Swap full + PSI enormous

→ memory-thrashing problem.

## `usb`, `uas`, `I/O error`, EXT4/JBD2

→ external storage problem.

## Only plasmashell malfunctioning

→ Plasma panel/shell issue.

## Kernel/panic/watchdog output

→ genuine lower-level operating-system crash.

This is exactly the classification Fedora Crash Doctor should automate.

---

# Step 3 — graceful recovery

Panel:

```bash
plasmashell --replace
```

Memory offender:

close/kill offending application.

Graphical session irrecoverable:

```bash
sudo systemctl reboot
```

Avoid the power button unless the TTY itself is impossible.

---

# Step 4 — immediately inspect the previous boot

After restart:

```bash
journalctl -b -1 -p warning
```

then:

```bash
journalctl -k -b -1 | grep -iE \
'i915|drm|gpu|hang|reset|oom|out of memory|killed process|blocked|nvme|usb|uas|ext4|btrfs|aer'
```

and run Fedora Crash Doctor.

---

# What I would change on AVANCE-WS7 now

## 1. Keep Fedora completely updated

```bash
sudo dnf upgrade --refresh
flatpak update
```

Fedora 44 currently has newer Plasma 6.7.x packages than some of the versions we were originally troubleshooting.

---

## 2. Keep VS Code GPU acceleration disabled

We've already done this.

I would leave it that way while troubleshooting.

---

## 3. Keep Chrome GPU acceleration disabled temporarily

Same principle.

Once the machine has been stable for a meaningful period, it can be re-enabled experimentally.

---

## 4. Keep Crash Doctor capture enabled

Especially:

* persistent journal
* canary
* desktop heartbeat
* kdump
* memory-pressure recording

Those turn a mystery freeze into evidence.

---

## 5. Make memory telemetry a first-class feature

This is perhaps the most important remaining Crash Doctor improvement.

For the minutes preceding a freeze, periodically record:

```text
available RAM
zram usage
swap usage
PSI memory
PSI I/O
system load
top processes by RSS
top processes by swap
systemd cgroup memory
```

The August 14 event proved why.

---

## 6. Do the single-monitor test

This is now worth doing.

Run for a meaningful period using one monitor.

If the i915 atomic-update freezes disappear, that's highly valuable evidence.

---

## 7. A/B test X11

Fedora 44 currently offers the independently-maintained `plasma-workspace-x11` package, even though Fedora KDE itself officially supports Wayland rather than X11.

Use it as a diagnostic experiment.

---

## 8. Treat USB instability separately

Any disk generating:

```text
USB disconnect
uas abort
I/O error
EXT4 error
JBD2 error
```

should immediately move to:

* another cable
* another port
* another enclosure

before blaming Fedora.

---

# My current model of your freezes

I think you've actually experienced at least **three different things that all feel like “Fedora froze”:**

### Type A — graphics freeze

```text
Intel i915
   ↓
DRM atomic display update
   ↓
KWin Wayland
   ↓
Plasma/Chrome/Code stop painting
   ↓
screen appears frozen

Linux remains alive
```

### Type B — resource freeze

```text
RAM exhausted
   ↓
zram/swap 100%
   ↓
memory reclaim
   ↓
extreme I/O pressure
   ↓
load explodes
   ↓
KWin starved
   ↓
desktop appears frozen

Linux remains barely alive
```

### Type C — Plasma-only freeze

```text
Plasma shell/panel
   ↓
taskbar / widgets freeze

KWin + applications + Linux remain healthy
```

That distinction explains why seemingly contradictory fixes have helped at different times.

---

# What I DON'T currently think is happening

Based on everything we've collected, I would **not** currently describe the machine as:

> “Fedora is unstable and randomly crashes.”

The evidence is much more specific.

Nor do I currently think we have good evidence for:

* dying internal SSD
* broken RPM database
* general filesystem corruption
* defective Fedora installation
* Realtek Wi-Fi being the primary crash cause
* SELinux causing the freezes
* firmware being badly outdated

---

# Highest-priority fix order

If this were my machine, my order would be:

**1. Update Fedora/Plasma/kernel fully.**

```bash
sudo dnf upgrade --refresh
```

**2. Keep Chrome + VS Code GPU acceleration disabled.**

**3. Keep Crash Doctor/canary/persistent journal running.**

**4. Fix the memory-pressure monitoring so we catch runaway processes before swap hits 100%.**

**5. Test Wayland with one monitor.**

**6. If freezes continue, test Plasma X11 as a controlled experiment.**

**7. Replace/test any flaky USB enclosure or cable independently.**

**8. Do not start adding random kernel parameters.**

**9. When the next freeze occurs, get to TTY before rebooting.**

That next live snapshot is likely to tell us whether **i915** or **memory pressure** is winning.

---

# Bottom line

The strongest story across all our work is:

> **AVANCE-WS7 is fundamentally healthy, but you've hit at least two nasty edge cases: Intel/KWin/Wayland multi-display instability and severe memory/zram pressure.**

Fedora Crash Doctor has already evolved enough to distinguish these instead of labelling everything a generic crash.

And the most useful thing we can do now isn't reinstall Fedora.

It's make the next freeze **impossible to hide its cause**.

# August 26 — v1.0 Stabilization and Live Maintenance

We completed the Fedora Crash Doctor v1.0 GUI and schema migration. We have full support for cancel-safe partial reports, asynchronous scan progress, and Btrfs/SMART status parsing.

Live diagnostics executed via passwordless sudo helper:
- **btrfs scrub**: finished with `0` corruption errors, `0` read/write errors.
- **nvme smart**: internal drive `nvme0n1` reports `media_errors: 0`, `critical_warning: 0`, `percentage_used: 30%`.
- **kdump**: confirmed operational (`kexec: loaded kdump kernel`).
- **persistent journal**: confirmed active and configured.
- **systemd-oomd**: active, protecting against desktop starvation.

The internal NVMe is demonstrably healthy. Previous IO errors were correctly attributed to a USB device, confirming our inheritance logic. The system is hardened and telemetry is active.
