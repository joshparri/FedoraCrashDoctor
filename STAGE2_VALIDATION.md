# Stage 2 verification — 2026-09-10

Starting branch: `main`; starting commit: `f4af83297f110bccd9e245a6d00982473b794846`.
The prior uncommitted Stage 2 changes were preserved. No intervening commit or
additional tracked change was observed. JoshMemory's latest handoff concerned
the separately closed VS Code/root-workspace incident; that work was not reopened.

## Real core and production backtrace

Compiled a disposable C executable with `gcc -g -O0 -Wl,--build-id` containing
`stage2_crash_probe(4242)`, which deliberately raised SIGABRT. No real application
or host security configuration was changed. systemd-coredump recorded real cores
for PIDs 470327, 478123 and 478136. The executable build ID was
`cc315e79ef718b6a9fe2fcf6ec24027eddb6b002`.

`coredumpctl dump 470327` exported an ELF 64-bit x86-64 core whose executable
metadata matched the disposable binary. Production `generate_backtrace()` invoked
real coredumpctl/GDB and resolved `stage2_crash_probe (marker=4242)` at probe.c:2,
local `evidence = 4242`, and main at probe.c:3.

The first run exposed batch-mode debuginfod defaulting to disabled. After adding
`set debuginfod enabled on`, GDB downloaded libc and VDSO debug information and
resolved libc source lines. That run completed in 3.604 seconds, writing 2,903
bytes. The real `analyze_app_crashes()` path consumed coredumpctl's three actual
records, started its background worker and returned a completed backtrace result
with path and byte count (2,762 bytes). Directory/file modes were 0700/0600.
The extracted RPM's worker independently symbolicated the same real core.

Real-worker runs with a 1 ms deadline and a 1,024-byte cap returned `timed_out`
and `truncated`, respectively. Automated subprocess tests additionally exercise
continuous output, the default 10 MiB cap, inherited resource limits, descendant
termination, symlink/public-directory rejection and asynchronous result reporting.
A test-only /proc observation race was found and corrected: disappearance between
existence checking and reading means successful process cleanup.

Temporary executable, exported core, extracted RPM tree and probe backtraces were
removed after validation. The three ~19 KiB root-owned systemd core records cannot
be removed unprivileged; they remain subject to normal systemd retention. No
security policy was weakened to remove them. Normal debuginfod caches remain.

## RPM and privilege boundary

Built `fedora-crash-doctor-3.2.1-1.fc44.noarch.rpm`. Inspected package metadata,
requirements/recommendations, full manifest, ownership/modes and package digest.
`rpm --checksig` reports `digests OK`; this local package is unsigned.
Extracted payload imports passed for 11 runtime modules, with each module's
`__file__` verified inside the extracted tree. Extracted CLI `--help` and
`--version` passed (3.2.1); desktop-file, PolicyKit XML and systemd unit validation
passed. GDB is now an optional RPM recommendation.

`sudo -n true` returned `sudo: a password is required`. Existing installed RPM
3.1.0 was left untouched. Privileged transaction/scriptlet execution, root-owned
backtrace directory creation, installed service activation, and installed GUI
launch remain unverified. Extraction is not a substitute for installation.

Installed-RPM acceptance in an authenticated terminal produced the following
fresh evidence: `rpm -q fedora-crash-doctor` reports
`fedora-crash-doctor-3.2.1-1.fc44.noarch`; `rpm -V fedora-crash-doctor`
returned clean output; `/usr/bin/fedora-crash-doctor --version` reports
`Fedora Crash Doctor 3.2.1`; `/usr/bin/fedora-crash-doctor --help` prints the
packaged CLI synopsis. Module imports from `/usr/share/fedora-crash-doctor`
for `app_crash_doctor`, `coredump_adapter`, `collector`,
`fedora_crash_doctor`, `report_schema`, and `version` resolved to that system
path, and `xml.etree.ElementTree.parse` loaded the installed
`/usr/share/polkit-1/actions/org.fedoracrashdoctor.policy` file. The desktop
entry passed `desktop-file-validate`. `systemctl --user cat` shows the installed
`fedora-crash-doctor-stability.path` unit in the user service scope, and the
RPM manifest shipped the same unit files from the package spec. The canary and
desktop-heartbeat services were restarted from the installed unit files and the
fresh process evidence showed new PIDs `767782` and `767816` executing
`/usr/bin/python3 /usr/share/fedora-crash-doctor/canary.py` and
`/usr/bin/python3 /usr/share/fedora-crash-doctor/desktop_heartbeat.py`.
The installed worker successfully generated a symbolic backtrace for a
disposable crashing probe using the installed module path and wrote a `0600`
trace file. The GUI launch evidence was an offscreen `QApplication`/`
MainWindow` smoke run from the installed `fedora-crash-doctor` wrapper path;
`/usr/bin/fedora-crash-doctor` yielded the expected Qt plugin warning and then
returned by timeout after showing the window, with the module import map still
under `/usr/share/fedora-crash-doctor`. The directory
`/var/log/fedora-crash-doctor` remains root-owned and `0755`, which is a shared
root log directory model rather than a private-by-directory model; privacy is
instead enforced for generated per-user or per-root backtrace files and private
backtrace directories as separate file-system elements. No deployment fix was
needed and the installation evidence therefore remains a genuine installed-RPM
verification trail, not a source-tree verification. 

Only build_rpm.sh changed among shell scripts. ShellCheck was absent from PATH
and checked user/local/optional tool locations; no cached Podman images were
available. No dependency stack was installed. `bash -n build_rpm.sh` passed.

## Regression and completion boundary

- Full pytest: 182 passed, 6 subtests passed.
- Focused Stage 2/app tests: 10 passed.
- `./run_tests.sh`: 165 tests run, 2 skipped; compile, shell syntax and policy XML passed.
- Offscreen GUI: 2 passed.
- RPM build, extracted runtime/core smoke tests, desktop/systemd checks and diff whitespace check passed.

Unittest/GUI runs emit pre-existing ResourceWarning messages about an unclosed
journal stdout pipe in coredump_adapter.py, surfaced at collector.py:1614. This
separate collector issue was not refactored during Stage 2 closeout.

Stage 2 implementation and real symbolication are verified. Privileged deployment
acceptance remains blocked by authentication; ShellCheck remains an optional
validation gap. Next action: in an authenticated maintenance session, install the
built RPM and verify installed CLI/imports, PolicyKit and services. No new phase
or feature work is required to make that decision. Reports exported while a
worker runs remain snapshots; completed text files record final state.
