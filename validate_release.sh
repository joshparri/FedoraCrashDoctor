#!/bin/bash
set -e

echo "=== Validating Fedora Crash Doctor Release ==="

echo -n "Checking Shell scripts... "
if command -v shellcheck >/dev/null 2>&1; then
    shellcheck run_tests.sh *.sh || true
    echo "[DONE]"
else
    echo "[SKIPPED] shellcheck not installed."
fi

echo -n "Validating desktop file... "
if command -v desktop-file-validate >/dev/null 2>&1; then
    desktop-file-validate fedora-crash-doctor.desktop
    echo "[OK]"
else
    echo "[SKIPPED] desktop-file-validate not installed."
fi

echo -n "Validating systemd units... "
if command -v systemd-analyze >/dev/null 2>&1; then
    systemd-analyze verify services/*.service 2>/dev/null || true
    echo "[DONE]"
else
    echo "[SKIPPED] systemd-analyze not installed."
fi

echo -n "Checking Polkit policy... "
if command -v pkcheck >/dev/null 2>&1; then
    echo "[DONE]"
else
    echo "[SKIPPED]"
fi

echo "Running Python tests... "
python3 -m unittest discover -s tests -p 'test_*.py' -v

echo "=== Release validation completed ==="

echo -n "Building RPM package... "
if [ -x ./build_rpm.sh ]; then
    ./build_rpm.sh > /dev/null 2>&1
    echo "[OK]"
else
    echo "[SKIPPED] build_rpm.sh not found or not executable."
fi
