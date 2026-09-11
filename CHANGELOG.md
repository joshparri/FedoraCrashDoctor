# Changelog

## Unreleased
- Added `incident_model.py`: each incident `collector.build_incidents()` produces now gets a stable `incident_id` and a `failure_scope` answering "WHAT stopped responding, and how much of the system?" (application, plasmashell_panel, compositor_session, whole_system, clean_shutdown, or `unknown` when evidence doesn't establish a more specific scope) -- kept strictly separate from WHY it happened, which remains collector.py's existing ranked `hypotheses` (unchanged; `mechanism_tags()` only normalises their categories for later fingerprinting, it doesn't re-rank them). A graphics-adjacent unclean shutdown is therefore `failure_scope=whole_system` with a leading `gpu_drm` mechanism tag -- confirmed impact plus a ranked, non-certain explanation -- rather than one mixed "GPU incident" label that would overstate what the evidence actually shows. `incident_id` is derived only from the boot and the boundary event's own raw anchor timestamp (not the padded evidence window, not the failure_boundary label, not confidence or attached evidence), so it survives widening the window, reclassifying the boundary, or joining more evidence onto the same incident later -- regression-tested directly. `evidence_completeness` uses explicit states (`complete`/`unavailable`/`not_collected`/...) instead of a boolean, so "no canary/heartbeat/user-observation evidence exists yet" is never read as "checked and healthy". This is a first, tested increment of the structured Incident model; joining canary/heartbeat telemetry and user-reported observations, fingerprinting/recurrence across boots, and a wizard for capturing "what did you see?" are not yet implemented.
- Symbolic backtraces are no longer started automatically as a side effect of parsing crash history (which silently launched GDB, with debuginfod enabled, as a background thread). `symbolic_analysis.start_symbolic_analysis()` is now the only way to run one: an explicit, deduplicated, cancellable job with `queued/running/completed/failed/timed_out/truncated/cancelled/unavailable` states. Network access is itself opt-in and explicit: `allow_network` defaults to `False` (local debug info only, debuginfod explicitly disabled, any inherited `DEBUGINFOD_URLS` stripped), and only a caller passing `allow_network=True` -- from a UI action that has told the user debuginfod may contact the network -- gets network-assisted symbolication. `generate_backtrace()` gained real cancellation support and reports `network_used` in its result.
- Removed the hardcoded "antigravity" special case from application-crash classification. There is no longer any application-specific default in the source at all: an executable's minimum-incident-count threshold before it's reported can only be lowered via an optional, user/site-editable JSON config file (`app_crash_doctor.load_min_incident_overrides()`), never a built-in list.
- Fixed `install.sh` (missing `app_crash_doctor`, `symbolic_analysis`, `coredump_adapter`, `graphics_doctor`, `hardware_doctor`, `memory_oom`, `dadlan_doctor` -- a script-installed system was missing modules the GUI imports) and added `tests/test_install_manifest.py`, an automated installed-tree smoke test that derives every module reachable from the shipped entry points, stages exactly what `install.sh`/the RPM spec would install into an isolated directory, and proves the application imports cleanly from that tree alone -- a regression test for this exact bug class.
- Fixed version drift: README and `install.sh`'s completion message hardcoded "3.2.0" while `VERSION` and the RPM spec said 3.2.1; `install.sh` now reads `VERSION` at install time and the README no longer hardcodes a version. Added `tests/test_version_consistency.py` (checks current package metadata only; historical `CHANGELOG.md`/RPM `%changelog` entries are untouched and remain free to mention old versions).
- Fixed `packaging/fedora-crash-doctor.spec`'s placeholder `https://localhost.invalid/...` URL (also present in the PolicyKit policy vendor URL, and in the report JSON schema `$id`, now the canonical `raw.githubusercontent.com` content URL for that file).
- Fixed `uninstall.sh` and the RPM `%preun` scriptlet to also disable/remove the stability `.path`/`.service` units and the desktop-heartbeat service, which install.sh/`%post` enable but neither uninstall path previously cleaned up.
- Replaced `run_tests.sh`'s and `validate_release.sh`'s use of `unittest discover` (which never ran the newer pytest-style test files) with `pytest` as the one authoritative test runner.
- Rewrote `validate_release.sh` to report `[PASS]`/`[FAIL]`/`[SKIP]` (with a reason) for each individual check instead of two dead-end PolicyKit branches that both silently printed `[SKIPPED]`, and to also verify the `.path` unit (previously only `*.service` was checked). Validation never installs build dependencies itself. Also fixed an rpmlint `explicit-lib-dependency` error by depending on the actual binary path (`/usr/bin/notify-send`) instead of the `libnotify` package name.
- Added `.github/workflows/ci.yml`: GitHub Actions CI running inside a real Fedora container (not Ubuntu) covering the Python suite, packaging manifest/version regressions, shell syntax/shellcheck, PolicyKit XML, desktop-file validation, systemd unit verification (including the `.path` unit), and an RPM build + rpmlint.
- Verified real systemd cores through the asynchronous analyser; enable debuginfod explicitly in batch mode, expose backtrace results, and use private user-state storage for unprivileged captures.
- Fixed background backtrace debugger arguments, absolute timeout, process cleanup, and 10 MiB output bound. Resource limits now run in a separate interpreter; private output creation rejects symlinks and records completion status.
- Derive the built RPM spec version from VERSION and include the application analysis runtime modules.

## 3.2.1 — 2026-08-27
- Fixed autoscan boot boundary to correctly inspect only the immediately preceding boot.
- Ensured dynamically generated storage (`storage_*`) and thermal (`thermal`) finding IDs contribute correctly to incident hypotheses.
- Updated GUI to correctly visualize nested PSI metrics from the canary schema.
- Made systemd-oomd audit compatible with flexible memory pressure configurations.
- Implemented structured journal source attribution (enforcing `_COMM` and `SYSLOG_IDENTIFIER` checks) to prevent unprivileged log-spoofing.
- Expanded automated regression suite (`tests/test_analysis.py`, `tests/test_autoscan.py`).

## 3.2.0 — 2026-08-27
- Hardened boot boundary logic to detect clean `systemd-shutdown` sequences and ignore historical crash artifacts.
- Implemented shutdown-context suppression window to ignore Wayland/Plasma teardown noise during clean reboots.
- Updated Wayland compositor regex to safely ignore `xkbcomp` and portal registration teardown errors.
- Removed dead `build_rpm` action from the privileged broker helper to reduce attack surface.

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
