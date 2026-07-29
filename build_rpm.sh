#!/usr/bin/env bash
set -euo pipefail
VERSION=3.0.0
NAME=fedora-crash-doctor
SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TOPDIR="${HOME}/rpmbuild"

if ! command -v rpmbuild >/dev/null 2>&1; then
  echo "Installing RPM build tools…"
  sudo dnf install -y rpm-build rpmdevtools
fi
rpmdev-setuptree
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/$NAME-$VERSION"
cp -a "$SOURCE_DIR"/. "$TMP/$NAME-$VERSION/"
rm -rf "$TMP/$NAME-$VERSION/.git"
tar -C "$TMP" -czf "$TOPDIR/SOURCES/$NAME-$VERSION.tar.gz" "$NAME-$VERSION"
cp "$SOURCE_DIR/packaging/$NAME.spec" "$TOPDIR/SPECS/"
rpmbuild -ba "$TOPDIR/SPECS/$NAME.spec"
echo "RPMs are under $TOPDIR/RPMS and $TOPDIR/SRPMS"
