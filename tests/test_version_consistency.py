"""Version-drift regression tests.

VERSION is the single source of truth for the application's version. These
tests pin the invariant that nothing else in the tree hardcodes a version
number that can silently drift from it -- this class of bug shipped before
(VERSION said 3.2.1 while README, install.sh's install message, and the RPM
spec's %changelog latest entry all still said 3.2.0).
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()

SEMVER_RE = re.compile(r"\b\d+\.\d+\.\d+\b")


def test_version_file_is_a_bare_semver():
    assert re.fullmatch(r"\d+\.\d+\.\d+", VERSION), (
        f"VERSION file should contain a bare X.Y.Z version, got {VERSION!r}"
    )


def test_rpm_spec_version_field_matches_version_file():
    spec = (ROOT / "packaging" / "fedora-crash-doctor.spec").read_text(encoding="utf-8")
    match = re.search(r"^Version:\s*(\S+)", spec, re.MULTILINE)
    assert match, "packaging/fedora-crash-doctor.spec has no Version: field"
    assert match.group(1) == VERSION, (
        f"spec Version field is {match.group(1)!r} but VERSION file is {VERSION!r} "
        "(build_rpm.sh overwrites this at build time, but the checked-in spec "
        "should still match so a manual `rpmbuild -ba` on the raw spec is correct too)"
    )


def test_rpm_spec_latest_changelog_entry_matches_version_file():
    spec = (ROOT / "packaging" / "fedora-crash-doctor.spec").read_text(encoding="utf-8")
    changelog = spec.split("%changelog", 1)[1]
    match = re.search(r"^\*.*-\s*(\d+\.\d+\.\d+)-\d+\s*$", changelog, re.MULTILINE)
    assert match, "packaging/fedora-crash-doctor.spec %changelog has no parseable entry"
    assert match.group(1) == VERSION, (
        f"newest %changelog entry describes {match.group(1)!r} but VERSION file "
        f"is {VERSION!r} -- add a %changelog entry when bumping VERSION"
    )


def test_install_sh_has_no_hardcoded_version_literal():
    install_sh = (ROOT / "install.sh").read_text(encoding="utf-8")
    hits = SEMVER_RE.findall(install_sh)
    assert not hits, (
        f"install.sh hardcodes version literal(s) {hits} instead of reading "
        "VERSION at runtime (use $(cat \"$SOURCE_DIR/VERSION\"))"
    )


def test_readme_title_has_no_hardcoded_version_literal():
    first_line = (ROOT / "README.md").read_text(encoding="utf-8").splitlines()[0]
    hits = SEMVER_RE.findall(first_line)
    assert not hits, (
        f"README.md title hardcodes version literal(s) {hits}, which will "
        "drift from VERSION; drop the version number from the title"
    )
