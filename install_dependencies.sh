#!/usr/bin/env bash
set -u
if [[ $EUID -ne 0 ]]; then
  echo "Run this installer as root." >&2
  exit 1
fi

required=(python3-pyside6 polkit systemd libnotify)
recommended=(
  gdb inxi smartmontools nvme-cli lm_sensors pciutils usbutils fwupd
  rasdaemon edac-utils fwts kexec-tools btrfs-progs stress-ng memtest86+
  iw ksystemlog gnome-disk-utility abrt abrt-cli gnome-abrt
)

echo "Installing required Fedora packages…"
dnf install -y "${required[@]}" || exit 1

echo
echo "Installing diagnostic packages individually so one unavailable optional package does not abort the install…"
for package in "${recommended[@]}"; do
  if rpm -q "$package" >/dev/null 2>&1; then
    echo "✓ $package already installed"
  elif dnf install -y "$package"; then
    echo "✓ installed $package"
  else
    echo "⚠ optional package unavailable or failed: $package"
  fi
done
