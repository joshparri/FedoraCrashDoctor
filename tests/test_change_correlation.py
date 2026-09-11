"""Tests for bounded, non-causal recent-change correlation."""
from __future__ import annotations

from datetime import datetime

from change_correlation import (
    PACKAGE_FAMILIES,
    correlate_recent_changes,
    current_kernel_cmdline_context,
    parse_rpm_last_line,
)


class TestParseRpmLastLine:
    def test_parses_a_real_format_line(self):
        line = "kernel-core-7.1.10-200.fc44.x86_64       Thu 10 Sep 2026 09:05:52 AM AEST"
        parsed = parse_rpm_last_line(line)
        assert parsed["name"] == "kernel-core"
        assert parsed["version"] == "7.1.10"
        assert parsed["release"] == "200.fc44"
        assert parsed["arch"] == "x86_64"
        assert parsed["installed_at"] == datetime(2026, 9, 10, 9, 5, 52)

    def test_handles_multi_hyphen_package_names(self):
        line = "linux-firmware-20260101-1.fc44.noarch    Mon 01 Sep 2026 08:00:00 AM AEST"
        parsed = parse_rpm_last_line(line)
        assert parsed["name"] == "linux-firmware"

    def test_blank_line_returns_none(self):
        assert parse_rpm_last_line("") is None
        assert parse_rpm_last_line("   \n") is None

    def test_malformed_line_returns_none_not_a_crash(self):
        assert parse_rpm_last_line("this is not an rpm --last line at all") is None

    def test_unparseable_date_returns_none(self):
        assert parse_rpm_last_line("some-package-1.0-1.noarch    not a real date") is None


class TestCorrelateRecentChanges:
    def _line(self, name, version, release, arch, dt: datetime) -> str:
        date_str = dt.strftime("%a %d %b %Y %I:%M:%S %p") + " AEST"
        return f"{name}-{version}-{release}.{arch}    {date_str}"

    def test_change_before_incident_is_reported_with_gap(self):
        incident_anchor = datetime(2026, 9, 10, 12, 0, 0)
        mesa_change = incident_anchor.replace(day=8)  # 2 days earlier
        output = self._line("mesa", "24.1.0", "1.fc44", "x86_64", mesa_change)
        results = correlate_recent_changes(output, incident_anchor)
        assert len(results) == 1
        assert results[0]["family"] == "graphics_mesa"
        assert "before this incident" in results[0]["note"]
        assert "causality is not established" in results[0]["note"]

    def test_change_after_incident_is_not_reported(self):
        incident_anchor = datetime(2026, 9, 10, 12, 0, 0)
        after = incident_anchor.replace(day=11)
        output = self._line("mesa", "24.1.0", "1.fc44", "x86_64", after)
        assert correlate_recent_changes(output, incident_anchor) == []

    def test_change_outside_lookback_window_is_not_reported(self):
        incident_anchor = datetime(2026, 9, 10, 12, 0, 0)
        long_ago = datetime(2026, 1, 1, 12, 0, 0)
        output = self._line("mesa", "24.1.0", "1.fc44", "x86_64", long_ago)
        assert correlate_recent_changes(output, incident_anchor, lookback_days=14) == []

    def test_untracked_package_family_is_ignored(self):
        incident_anchor = datetime(2026, 9, 10, 12, 0, 0)
        output = self._line("some-random-app", "1.0", "1.fc44", "x86_64", incident_anchor.replace(day=9))
        assert correlate_recent_changes(output, incident_anchor) == []

    def test_only_the_closest_change_per_family_is_reported(self):
        incident_anchor = datetime(2026, 9, 10, 12, 0, 0)
        older = incident_anchor.replace(day=1)
        closer = incident_anchor.replace(day=9)
        output = "\n".join([
            self._line("kernel-core", "7.1.10", "200.fc44", "x86_64", older),
            self._line("kernel-core", "7.1.13", "200.fc44", "x86_64", closer),
        ])
        results = correlate_recent_changes(output, incident_anchor)
        assert len(results) == 1
        assert results[0]["version"] == "7.1.13-200.fc44"

    def test_results_sorted_closest_to_incident_first(self):
        incident_anchor = datetime(2026, 9, 10, 12, 0, 0)
        output = "\n".join([
            self._line("mesa", "24.1.0", "1.fc44", "x86_64", incident_anchor.replace(day=1)),
            self._line("kernel-core", "7.1.13", "200.fc44", "x86_64", incident_anchor.replace(day=9)),
        ])
        results = correlate_recent_changes(output, incident_anchor)
        assert [r["family"] for r in results] == ["kernel", "graphics_mesa"]

    def test_malformed_lines_are_skipped_not_fatal(self):
        incident_anchor = datetime(2026, 9, 10, 12, 0, 0)
        output = "garbage line\n" + self._line("mesa", "24.1.0", "1.fc44", "x86_64", incident_anchor.replace(day=9))
        results = correlate_recent_changes(output, incident_anchor)
        assert len(results) == 1

    def test_never_claims_causation_language(self):
        incident_anchor = datetime(2026, 9, 10, 12, 0, 0)
        output = self._line("plasma-workspace", "6.5.0", "1.fc44", "x86_64", incident_anchor.replace(day=9))
        results = correlate_recent_changes(output, incident_anchor)
        note = results[0]["note"].lower()
        assert "caused" not in note
        assert "causality is not established" in note

    def test_all_declared_families_are_matchable(self):
        """Guard against a family being declared but its prefix matching
        never actually firing for a realistic package name."""
        incident_anchor = datetime(2026, 9, 10, 12, 0, 0)
        sample_names = {
            "kernel": "kernel-core",
            "graphics_mesa": "mesa-dri-drivers",
            "linux_firmware": "linux-firmware",
            "desktop_kwin_plasma": "plasma-workspace",
            "audio_stack": "pipewire",
        }
        assert set(sample_names) == set(PACKAGE_FAMILIES)
        for family, name in sample_names.items():
            output = self._line(name, "1.0", "1.fc44", "x86_64", incident_anchor.replace(day=9))
            results = correlate_recent_changes(output, incident_anchor)
            assert results and results[0]["family"] == family, f"{name} did not match {family}"


class TestKernelCmdlineContext:
    def test_returns_current_cmdline_without_claiming_a_change(self):
        result = current_kernel_cmdline_context("BOOT_IMAGE=... quiet\n")
        assert result["current_cmdline"] == "BOOT_IMAGE=... quiet"
        assert result["change_detected"] is None
