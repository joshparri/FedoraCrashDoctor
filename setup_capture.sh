#!/usr/bin/env bash
set -u
if [[ $EUID -ne 0 ]]; then
  echo "Crash capture setup must run as root."
  exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
bash "$SCRIPT_DIR/install_dependencies.sh"

echo
echo "Configuring persistent system journal…"
install -d -m 2755 /var/log/journal
install -d -m 0755 /etc/systemd/journald.conf.d
cat >/etc/systemd/journald.conf.d/99-fedora-crash-doctor.conf <<'EOF'
[Journal]
Storage=persistent
SystemMaxUse=1G
MaxRetentionSec=30day
Compress=yes
EOF
systemctl restart systemd-journald
journalctl --flush || true

enable_if_present() {
  local unit="$1"
  if systemctl list-unit-files "$unit" --no-legend 2>/dev/null | grep -q "^$unit"; then
    systemctl enable --now "$unit" || true
  else
    echo "Optional unit not available: $unit"
  fi
}

echo
echo "Enabling hardware and application crash collectors…"
enable_if_present rasdaemon.service
enable_if_present abrtd.service
enable_if_present abrt-journal-core.service
enable_if_present cockpit.socket

echo
echo "Preparing kdump kernel crash capture…"
if command -v kdumpctl >/dev/null 2>&1; then
  if kdumpctl reset-crashkernel; then
    echo "Crashkernel reservation written to installed kernel entries."
  else
    echo "kdumpctl could not set the crashkernel reservation automatically."
  fi
  systemctl enable kdump.service || true
  echo "Kdump status before reboot:"
  kdumpctl status || true
  echo
  echo "A reboot is required before the crashkernel reservation can be active."
else
  echo "kdumpctl is unavailable; kdump was not configured."
fi

echo
echo "Crash capture setup complete. No data is uploaded."
