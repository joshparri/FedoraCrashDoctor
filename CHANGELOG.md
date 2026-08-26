# Changelog

## Unreleased

- Added `HISTORY.md` with the full Fedora/Linux crash and freeze master record,
  including diagnosis rankings, chronology, recovery procedure, and current
  improvement priorities.
- Linked the master record from the README.
- Added `TODO.md` with the release-hardening worklist and linked it from the
  README.
- Added a read-only host stability audit for live AVANCE-WS7 prevention checks.
- Added an explicit CLI mode with `--help`, `--version`, and `--cli --scan`.
- Split expensive RPM file verification into explicit `deep` scan mode so
  ordinary full scans stay more responsive.
- Added `validate_release.sh` for broad, CI-friendly best-effort validation.
- Added a repository desktop file for installer and packaging validation.
- Moved manual diagnostic experiments under `tools/manual/` so root-level
  unittest discovery no longer imports them as tests.

## 3.1.0 — 2026-07-29

- Added issue-specific Fix / next steps cards with command copy/run/explain controls.
- Added safer launchers for display settings, filtered logs, evidence capture,
  kdump validation and scan-after-reboot scheduling.
- Added manual verification tracking for rebooted, one-monitor tested, stable
  and still-freezing outcomes.
- Added before/after comparison for saved scans.
- Improved PCIe device naming with likely user-facing roles.
- Replaced vague category warnings with more specific next-action labels.
- Hardened canary analysis against null desktop heartbeat samples.

## 3.0.0 — 2026-07-29

- Added incident timeline and evidence proximity.
- Added ranked hypotheses with confidence and A/B tests.
- Added category health cards and finding filters.
- Added real progress and cancellation.
- Added secure long-lived PolicyKit broker for one prompt per app session.
- Added improved PCIe address-to-device correlation.
- Reclassified perf sampling messages as context rather than crash prediction.
- Expanded system canary with PSI and desktop/KWin heartbeat correlation.
- Made Cockpit explicitly optional.
- Added controlled SMART, Btrfs, Memtest, CPU and RAM tests.
- Added safe kdump validation.
- Added RPM packaging files and regression tests.
