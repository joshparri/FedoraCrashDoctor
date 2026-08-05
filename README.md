# Fedora Crash Doctor v3

A local Qt 6 diagnostic application for Fedora KDE and other Fedora desktops.
It is designed to answer three questions after a crash:

1. **What happened closest to the crash?**
2. **What causes best fit the collected evidence?**
3. **What controlled test would strengthen or weaken each explanation?**

## What changed in v3

- **One authentication prompt per app session.** The GUI launches one root-owned,
  action-whitelisted broker through PolicyKit. The broker remains attached to
  that GUI process and exits when the app closes. Buttons do not launch arbitrary
  `python3` or `bash` commands through `pkexec`.
- The PolicyKit default is `auth_admin_keep`. The long-lived broker is what avoids
  repeated prompts for the rest of that app session.
- **Incident timeline** separates events within ten minutes of the journal ending,
  earlier messages from the same boot, and historical background warnings.
- **Ranked likely causes** include confidence, supporting evidence, counter-evidence,
  the best next test, and what would strengthen or weaken the hypothesis.
- **Category cards** for Graphics, Memory, Storage, Thermals, PCIe/Network,
  Firmware and Software.
- **Determinate progress**, current scan step, and a Cancel button.
- Finding filters for **This incident**, **New**, **Recurring** and serious items.
- A **Fix / next steps** workflow with issue-specific fix cards, command blocks,
  copy/run/explain buttons, KDE Display Settings and filtered-log launchers,
  scan-after-reboot scheduling, and manual verification tracking.
- Before/after scan comparison highlights findings that disappeared, stayed
  recurring, or newly appeared after a change.
- Plain-English category labels such as **Try display-safe mode** and
  **Check PCIe device** replace vague “needs attention” wording where the
  evidence supports a more specific next move.
- Corrected PCIe events are joined to the actual `lspci -Dnnk` address, device
  description, likely user-facing device role and active kernel driver. The
  address can appear anywhere in the AER log line.
- `perf: interrupt took too long` is treated as contextual information about perf
  sampling-rate adjustment, not a reliable crash predictor by itself.
- The low-write **system canary** captures CPU/memory/I/O PSI, temperatures, CPU
  frequency, GPU telemetry where exposed, Wi-Fi signal, display connectors and
  top processes. It samples every 15 seconds, rotates logs, and fsyncs once per
  minute rather than on every sample.
- A per-user **desktop/KWin heartbeat** is correlated with the system canary:
  - system canary continues while desktop heartbeat fails → compositor/session
    failure becomes more likely;
  - both stop together → kernel, firmware, power or total-system lock becomes
    more likely.
- **Cockpit is optional** and is never enabled merely by turning on crash capture.
- Separate, confirmed tests for SMART short self-tests, Btrfs scrub, Memtest boot
  readiness, five-minute CPU stress and five-minute RAM stress.
- Safe kdump readiness validation without forcing a panic.
- HTML, JSON and concise support-text exports with optional privacy redaction.
- RPM packaging files and a `build_rpm.sh` helper.

## Install or upgrade from v1/v2

Extract the zip, open a terminal inside the `fedora-crash-doctor` folder, then run:

```bash
chmod +x *.sh *.py
sudo ./install.sh
```

The installer removes the old `/opt/fedora-crash-doctor` copy and old v2 service
unit overrides after v3 is safely installed. Existing reports and captured logs
are preserved.

Open the KDE application launcher and search for **Fedora Crash Doctor**.

## Development setup

To work on Fedora Crash Doctor locally without installing it system-wide:

1. Open a terminal inside the project directory.
2. Ensure you have standard Python 3 and basic KDE dependencies installed.
3. Run the test suite: `./run_tests.sh`
4. Run the main GUI application: `python3 fedora_crash_doctor.py`
5. Generate a test scan manually (writes a JSON report): `python3 collector.py --output test_scan.json`

## Recommended first use

1. Open Fedora Crash Doctor.
2. Select **Enable crash capture**.
3. Leave Cockpit unticked unless you specifically want its local web interface.
4. Reboot.
5. Run a **Quick scan**.
6. After another crash, let the boot-time autoscan load, then review the incident
   timeline and ranked causes.
7. Open **Fix / next steps**, copy or run the suggested commands, mark what you
   changed, reboot if requested, and run another scan to compare before/after.

## Privilege model

The only executable PolicyKit authorises is:

```text
/usr/libexec/fedora-crash-doctor/fedora-crash-doctor-helper
```

It accepts newline-delimited JSON through a private pipe from the GUI and only
implements named actions such as `scan`, `setup_capture`, `smart_short` and
`kdump_validate`. It rejects arbitrary commands and user-supplied output paths.
Reports are returned through the private pipe and saved by the unprivileged GUI.

Closing the application closes the privileged broker. Cancelling an action also
closes it, so the next privileged action asks again.

A passwordless PolicyKit rule example is included under `extras/`, but is not
installed. It is less secure and generally unnecessary because v3 already asks
only once while the application remains open.

## Controlled tests

Normal scans are read-only and never automatically run:

- stress-ng
- Memtest86+
- SMART self-tests
- Btrfs scrub
- filesystem repair
- forced kernel panic tests

Each available test has a separate confirmation. CPU and RAM stress tests are
fixed at five minutes. There is intentionally no automatic forced-panic kdump
validation.

## Data locations

User reports:

```text
~/Documents/Fedora Crash Doctor Reports/
```

System canary:

```text
/var/log/fedora-crash-doctor/canary.log
```

Boot-time autoscan and private baselines:

```text
/var/lib/fedora-crash-doctor/
```

## Limits

No diagnostic application can guarantee a cause for every hard crash. Sudden
power loss, firmware deadlock, motherboard failure or some GPU lockups can stop
the machine before the final evidence is written. Ranked causes are explicit
hypotheses based on the evidence available, not certainty.
