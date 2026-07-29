#!/usr/bin/env python3
from __future__ import annotations

import html
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from PySide6.QtCore import QObject, QProcess, Qt, QTimer, QUrl, Signal
from PySide6.QtGui import QColor, QDesktopServices, QPainter, QPen
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QDialog, QFileDialog, QFormLayout,
    QFrame, QGridLayout, QHBoxLayout, QHeaderView, QLabel, QMainWindow,
    QInputDialog, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QScrollArea,
    QSplitter, QTabWidget, QTableWidget, QTableWidgetItem, QTextBrowser,
    QVBoxLayout, QWidget,
)

APP_DIR = Path(__file__).resolve().parent
INSTALLED_HELPER = Path("/usr/libexec/fedora-crash-doctor/fedora-crash-doctor-helper")
HELPER = INSTALLED_HELPER if INSTALLED_HELPER.exists() else APP_DIR / "privileged_helper.py"
VERSION = "3.0.0"
SEVERITY_ICON = {"critical": "🔴", "warning": "🟠", "info": "🔵"}
STATUS_ICON = {"new": "NEW", "recurring": "Recurring"}


class PrivilegeBroker(QObject):
    ready_changed = Signal(bool)
    message = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.process: QProcess | None = None
        self.buffer = ""
        self.ready = False
        self.pending_start: list[Callable[[], None]] = []
        self.requests: dict[str, dict[str, Any]] = {}
        self.cancelling = False

    def ensure(self, callback: Callable[[], None]) -> None:
        if self.ready and self.process and self.process.state() == QProcess.ProcessState.Running:
            callback()
            return
        self.pending_start.append(callback)
        if self.process and self.process.state() != QProcess.ProcessState.NotRunning:
            return
        self.process = QProcess(self)
        self.process.setProcessChannelMode(QProcess.ProcessChannelMode.SeparateChannels)
        self.process.readyReadStandardOutput.connect(self._read_stdout)
        self.process.readyReadStandardError.connect(self._read_stderr)
        self.process.finished.connect(self._finished)
        self.message.emit("Authorising one locked-down helper for this app session…")
        self.process.start("pkexec", [str(HELPER), "broker"])

    def request(
        self,
        action: str,
        params: dict[str, Any] | None,
        result_cb: Callable[[bool, Any], None],
        progress_cb: Callable[[int, int, str], None] | None = None,
    ) -> str:
        request_id = uuid.uuid4().hex

        self.requests[request_id] = {"result": result_cb, "progress": progress_cb}

        def send_request() -> None:
            if not self.process:
                request = self.requests.pop(request_id, None)
                if request:
                    request["result"](False, "Privileged helper is unavailable.")
                return
            payload = {"id": request_id, "action": action, "params": params or {}}
            self.process.write((json.dumps(payload, separators=(",", ":")) + "\n").encode())

        self.ensure(send_request)
        return request_id

    def cancel_all(self) -> None:
        self.cancelling = True
        if self.process and self.process.state() != QProcess.ProcessState.NotRunning:
            self.process.closeWriteChannel()
            self.process.terminate()
            if not self.process.waitForFinished(2500):
                self.process.kill()
                self.process.waitForFinished(5000)
        for item in list(self.requests.values()):
            item["result"](False, "Cancelled. The session helper was closed; the next privileged action will ask again.")
        self.requests.clear()
        self.ready = False
        self.ready_changed.emit(False)

    def _read_stdout(self) -> None:
        if not self.process:
            return
        self.buffer += bytes(self.process.readAllStandardOutput()).decode(errors="replace")
        while "\n" in self.buffer:
            line, self.buffer = self.buffer.split("\n", 1)
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except Exception:
                self.message.emit(f"Helper output was not valid JSON: {line[:200]}")
                continue
            event_type = event.get("type")
            if event_type == "ready":
                self.ready = True
                self.ready_changed.emit(True)
                self.message.emit("Administrator authorisation is active for this app session.")
                callbacks, self.pending_start = self.pending_start, []
                for callback in callbacks:
                    callback()
            elif event_type == "progress":
                request = self.requests.get(event.get("id"))
                if request and request.get("progress"):
                    request["progress"](int(event.get("current", 0)), int(event.get("total", 0)), str(event.get("label", "")))
            elif event_type == "result":
                request = self.requests.pop(event.get("id"), None)
                if request:
                    request["result"](bool(event.get("ok")), event.get("data") if event.get("ok") else event.get("error", "Unknown helper error"))

    def _read_stderr(self) -> None:
        if self.process:
            text = bytes(self.process.readAllStandardError()).decode(errors="replace").strip()
            if text:
                self.message.emit(text[-1500:])

    def _finished(self, code: int, _status) -> None:
        was_ready = self.ready
        self.ready = False
        self.ready_changed.emit(False)
        if self.requests:
            reason = "Cancelled." if self.cancelling else f"Privileged helper exited with code {code}."
            for item in list(self.requests.values()):
                item["result"](False, reason)
            self.requests.clear()
        self.cancelling = False
        if not was_ready and self.pending_start:
            callbacks, self.pending_start = self.pending_start, []
            for callback in callbacks:
                # Callers receive the failure through a synthetic request only if one exists.
                pass


class StatusCard(QFrame):
    def __init__(self, title: str, value: str = "—"):
        super().__init__()
        self.setFrameShape(QFrame.Shape.StyledPanel)
        layout = QVBoxLayout(self)
        self.title = QLabel(title)
        self.value = QLabel(value)
        self.value.setStyleSheet("font-size: 22px; font-weight: 700;")
        layout.addWidget(self.title)
        layout.addWidget(self.value)

    def set_state(self, label: str, state: str = "neutral") -> None:
        colours = {
            "critical": "#b42318", "warning": "#b54708", "passed": "#067647",
            "not_checked": "#667085", "neutral": "#344054",
        }
        self.value.setText(label)
        self.value.setStyleSheet(f"font-size: 18px; font-weight: 700; color: {colours.get(state, colours['neutral'])};")


class TrendChart(QWidget):
    def __init__(self):
        super().__init__()
        self.series: list[tuple[str, list[float], QColor]] = []
        self.setMinimumHeight(230)

    def set_series(self, series: list[tuple[str, list[float], QColor]]) -> None:
        self.series = series
        self.update()

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = self.rect().adjusted(50, 20, -20, -35)
        painter.setPen(QPen(QColor("#98a2b3"), 1))
        painter.drawRect(rect)
        values = [value for _, points, _ in self.series for value in points]
        maximum = max(values + [1])
        for step in range(5):
            y = rect.bottom() - rect.height() * step / 4
            painter.drawLine(rect.left(), int(y), rect.right(), int(y))
            painter.drawText(5, int(y + 5), str(round(maximum * step / 4, 1)))
        for name, points, colour in self.series:
            if not points:
                continue
            painter.setPen(QPen(colour, 2))
            previous = None
            for index, value in enumerate(points):
                x = rect.left() + (rect.width() * index / max(1, len(points) - 1))
                y = rect.bottom() - rect.height() * value / maximum
                if previous:
                    painter.drawLine(int(previous[0]), int(previous[1]), int(x), int(y))
                painter.drawEllipse(int(x - 2), int(y - 2), 4, 4)
                previous = (x, y)
        legend_x = rect.left()
        for name, _, colour in self.series:
            painter.setPen(QPen(colour, 3))
            painter.drawLine(legend_x, self.height() - 15, legend_x + 18, self.height() - 15)
            painter.setPen(QPen(QColor("#344054"), 1))
            painter.drawText(legend_x + 24, self.height() - 10, name)
            legend_x += 120


class CaptureDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Enable crash capture")
        layout = QVBoxLayout(self)
        text = QLabel(
            "This enables persistent journals, rasdaemon, ABRT where available, the low-write system canary, "
            "the desktop/KWin heartbeat, boot-time autoscan and kdump. Kdump reserves some RAM and needs a reboot."
        )
        text.setWordWrap(True)
        self.cockpit = QCheckBox("Also install and enable Cockpit on port 9090 (optional)")
        self.cockpit.setChecked(False)
        buttons = QHBoxLayout()
        cancel = QPushButton("Cancel")
        enable = QPushButton("Enable capture")
        cancel.clicked.connect(self.reject)
        enable.clicked.connect(self.accept)
        buttons.addStretch()
        buttons.addWidget(cancel)
        buttons.addWidget(enable)
        layout.addWidget(text)
        layout.addWidget(self.cockpit)
        layout.addLayout(buttons)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"Fedora Crash Doctor {VERSION}")
        screen = QApplication.primaryScreen()
        if screen:
            available = screen.availableGeometry()
            width = min(1180, max(360, available.width() - 80))
            height = min(720, max(360, available.height() - 80))
            self.resize(width, height)
            self.move(
                available.x() + max(0, (available.width() - width) // 2),
                available.y() + max(0, (available.height() - height) // 2),
            )
        else:
            self.resize(1100, 700)
        self.report: dict[str, Any] | None = None
        self.report_dir = Path.home() / "Documents" / "Fedora Crash Doctor Reports"
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.broker = PrivilegeBroker(self)
        self.broker.ready_changed.connect(self.auth_changed)
        self.broker.message.connect(self.set_status)
        self.busy = False
        self.build_ui()
        self.load_pending_autoscan()
        self.refresh_trends()

    def build_ui(self) -> None:
        root = QWidget()
        outer = QVBoxLayout(root)

        heading = QHBoxLayout()
        title_box = QVBoxLayout()
        title = QLabel("Fedora Crash Doctor")
        title.setStyleSheet("font-size: 26px; font-weight: 750;")
        subtitle = QLabel("Evidence-weighted crash diagnostics, timelines and controlled tests")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        self.auth_badge = QLabel("🔒 Authorisation not started")
        self.auth_badge.setStyleSheet("padding: 7px 10px; border: 1px solid #d0d5dd; border-radius: 8px;")
        heading.addLayout(title_box)
        heading.addStretch()
        heading.addWidget(self.auth_badge)
        outer.addLayout(heading)

        actions = QHBoxLayout()
        self.quick_btn = QPushButton("Quick scan")
        self.full_btn = QPushButton("Full scan")
        self.cancel_btn = QPushButton("Cancel current action")
        self.cancel_btn.setEnabled(False)
        self.capture_btn = QPushButton("Enable crash capture")
        self.tools_btn = QPushButton("Install/repair tools")
        self.logs_btn = QPushButton("KDE System Log")
        self.disks_btn = QPushButton("Disks")
        for button in (self.quick_btn, self.full_btn, self.cancel_btn, self.capture_btn, self.tools_btn, self.logs_btn, self.disks_btn):
            actions.addWidget(button)
        actions.addStretch()
        outer.addLayout(actions)
        self.quick_btn.clicked.connect(lambda: self.run_scan("quick"))
        self.full_btn.clicked.connect(lambda: self.run_scan("full"))
        self.cancel_btn.clicked.connect(self.cancel_action)
        self.capture_btn.clicked.connect(self.enable_capture)
        self.tools_btn.clicked.connect(self.install_tools)
        self.logs_btn.clicked.connect(lambda: self.launch(["ksystemlog"]))
        self.disks_btn.clicked.connect(lambda: self.launch(["gnome-disks"]))

        overall_frame = QFrame()
        overall_frame.setFrameShape(QFrame.Shape.StyledPanel)
        overall_layout = QVBoxLayout(overall_frame)
        self.overall_title = QLabel("Run a scan to rank likely causes")
        self.overall_title.setStyleSheet("font-size: 19px; font-weight: 700;")
        self.overall_summary = QLabel("The app separates evidence near the crash from older background warnings.")
        self.overall_summary.setWordWrap(True)
        overall_layout.addWidget(QLabel("Overall assessment"))
        overall_layout.addWidget(self.overall_title)
        overall_layout.addWidget(self.overall_summary)
        outer.addWidget(overall_frame)

        cards_grid = QGridLayout()
        self.cards: dict[str, StatusCard] = {}
        for index, category in enumerate(["Graphics", "Memory", "Storage", "Thermals", "PCIe / Network", "Firmware", "Software"]):
            card = StatusCard(category)
            self.cards[category] = card
            cards_grid.addWidget(card, index // 4, index % 4)
        outer.addLayout(cards_grid)

        status_line = QHBoxLayout()
        self.status = QLabel("Ready. The first privileged action asks once; later actions reuse the same locked-down helper while this app stays open.")
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.hide()
        status_line.addWidget(self.status, 1)
        status_line.addWidget(self.progress)
        outer.addLayout(status_line)

        self.tabs = QTabWidget()
        outer.addWidget(self.tabs, 1)
        self.build_findings_tab()
        self.build_hypotheses_tab()
        self.build_timeline_tab()
        self.build_evidence_tab()
        self.build_capture_tab()
        self.build_tests_tab()
        self.build_fixes_tab()
        self.build_trends_tab()
        self.build_export_tab()
        self.setCentralWidget(root)

    def build_findings_tab(self) -> None:
        page = QWidget(); layout = QVBoxLayout(page)
        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("Show:"))
        self.finding_filter = QComboBox()
        self.finding_filter.addItems(["All findings", "This incident", "New", "Recurring", "Warnings and critical only"])
        self.finding_filter.currentIndexChanged.connect(self.populate_findings)
        fix_btn = QPushButton("Show fix")
        fix_btn.clicked.connect(self.show_fix_for_selection)
        filter_row.addWidget(self.finding_filter)
        filter_row.addWidget(fix_btn)
        filter_row.addStretch()
        layout.addLayout(filter_row)
        splitter = QSplitter(Qt.Orientation.Vertical)
        self.findings_table = QTableWidget(0, 6)
        self.findings_table.setHorizontalHeaderLabels(["Severity", "Scope", "Status", "Category", "Finding", "Confidence"])
        self.findings_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        for column in (0, 1, 2, 3, 5):
            self.findings_table.horizontalHeader().setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
        self.findings_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.findings_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.findings_table.itemSelectionChanged.connect(self.show_finding)
        self.finding_detail = QTextBrowser()
        splitter.addWidget(self.findings_table); splitter.addWidget(self.finding_detail)
        splitter.setSizes([390, 250])
        layout.addWidget(splitter)
        self.tabs.addTab(page, "Findings")

    def build_hypotheses_tab(self) -> None:
        page = QWidget(); layout = QVBoxLayout(page)
        intro = QLabel("Hypotheses are ranked by evidence. Each one shows support, counter-evidence and a test that can strengthen or weaken it.")
        intro.setWordWrap(True); layout.addWidget(intro)
        splitter = QSplitter(Qt.Orientation.Vertical)
        self.hyp_table = QTableWidget(0, 5)
        self.hyp_table.setHorizontalHeaderLabels(["Rank", "Confidence", "Score", "Category", "Hypothesis"])
        self.hyp_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.hyp_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.hyp_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.hyp_table.itemSelectionChanged.connect(self.show_hypothesis)
        self.hyp_detail = QTextBrowser()
        splitter.addWidget(self.hyp_table); splitter.addWidget(self.hyp_detail)
        splitter.setSizes([310, 330])
        layout.addWidget(splitter)
        self.tabs.addTab(page, "Likely causes")

    def build_timeline_tab(self) -> None:
        page = QWidget(); layout = QVBoxLayout(page)
        self.timeline_table = QTableWidget(0, 4)
        self.timeline_table.setHorizontalHeaderLabels(["Time", "Proximity", "Category", "Event"])
        self.timeline_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.timeline_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.timeline_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.timeline_table.itemSelectionChanged.connect(self.show_timeline)
        self.timeline_detail = QPlainTextEdit(); self.timeline_detail.setReadOnly(True)
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self.timeline_table); splitter.addWidget(self.timeline_detail)
        splitter.setSizes([420, 180]); layout.addWidget(splitter)
        self.tabs.addTab(page, "Incident timeline")

    def build_evidence_tab(self) -> None:
        page = QWidget(); layout = QHBoxLayout(page)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.checks_table = QTableWidget(0, 4)
        self.checks_table.setHorizontalHeaderLabels(["Category", "Check", "Status", "Time"])
        self.checks_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.checks_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.checks_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.checks_table.itemSelectionChanged.connect(self.show_check)
        self.check_output = QPlainTextEdit(); self.check_output.setReadOnly(True)
        splitter.addWidget(self.checks_table); splitter.addWidget(self.check_output)
        splitter.setSizes([430, 800]); layout.addWidget(splitter)
        self.tabs.addTab(page, "Raw evidence")

    def build_capture_tab(self) -> None:
        page = QWidget(); layout = QVBoxLayout(page)
        text = QLabel(
            "Crash capture improves the chance that the next failure leaves usable evidence. Cockpit is deliberately optional and is not enabled by default."
        )
        text.setWordWrap(True)
        buttons = QHBoxLayout()
        refresh = QPushButton("Check capture readiness")
        validate = QPushButton("Validate kdump safely")
        cockpit = QPushButton("Install/open Cockpit (optional)")
        refresh.clicked.connect(self.refresh_capture_status)
        validate.clicked.connect(self.validate_kdump)
        cockpit.clicked.connect(self.install_cockpit)
        buttons.addWidget(refresh); buttons.addWidget(validate); buttons.addWidget(cockpit); buttons.addStretch()
        self.capture_output = QPlainTextEdit(); self.capture_output.setReadOnly(True)
        layout.addWidget(text); layout.addLayout(buttons); layout.addWidget(self.capture_output, 1)
        self.tabs.addTab(page, "Crash capture")

    def build_tests_tab(self) -> None:
        page = QWidget(); layout = QVBoxLayout(page)
        warning = QLabel(
            "These tests are never run by a scan. They can heat, slow, interrupt or reboot the workstation. Start them only when a five-minute interruption is acceptable and save work first."
        )
        warning.setWordWrap(True); warning.setStyleSheet("font-weight: 650;")
        form = QFormLayout()
        self.smart_device = QComboBox()
        smart_btn = QPushButton("Start SMART short self-test")
        smart_row = QHBoxLayout(); smart_row.addWidget(self.smart_device); smart_row.addWidget(smart_btn)
        smart_wrap = QWidget(); smart_wrap.setLayout(smart_row)
        form.addRow("Drive:", smart_wrap)
        buttons = QHBoxLayout()
        memtest_btn = QPushButton("Verify Memtest boot entry")
        scrub_btn = QPushButton("Run Btrfs scrub")
        cpu_btn = QPushButton("CPU stress — 5 min")
        memory_btn = QPushButton("RAM stress — 5 min")
        for button in (memtest_btn, scrub_btn, cpu_btn, memory_btn): buttons.addWidget(button)
        buttons.addStretch()
        self.test_output = QPlainTextEdit(); self.test_output.setReadOnly(True)
        smart_btn.clicked.connect(self.smart_test)
        memtest_btn.clicked.connect(lambda: self.run_test("memtest_status", {}, "Verify the Memtest package and boot files?", False))
        scrub_btn.clicked.connect(lambda: self.run_test("btrfs_scrub", {}, "Run a read/verify Btrfs scrub of the root filesystem now? This can take a long time and increase disk activity.", True))
        cpu_btn.clicked.connect(lambda: self.run_test("stress_cpu", {}, "Run all CPU cores under stress for exactly five minutes? Save work first.", True))
        memory_btn.clicked.connect(lambda: self.run_test("stress_memory", {}, "Allocate and exercise about 60% of RAM for exactly five minutes? Save work first.", True))
        layout.addWidget(warning); layout.addLayout(form); layout.addLayout(buttons); layout.addWidget(self.test_output, 1)
        self.tabs.addTab(page, "Controlled tests")

    def build_fixes_tab(self) -> None:
        page = QWidget(); layout = QVBoxLayout(page)
        controls = QHBoxLayout()
        self.fix_focus = QComboBox()
        self.fix_focus.addItems(["Selected finding", "Top likely cause", "All needs-attention items"])
        self.fix_focus.currentIndexChanged.connect(self.populate_fixes)
        capture_btn = QPushButton("Enable evidence capture")
        kdump_btn = QPushButton("Validate kdump")
        rescan_btn = QPushButton("Run quick scan after changes")
        capture_btn.clicked.connect(self.enable_capture)
        kdump_btn.clicked.connect(self.validate_kdump)
        rescan_btn.clicked.connect(lambda: self.run_scan("quick"))
        controls.addWidget(QLabel("Fix plan for:"))
        controls.addWidget(self.fix_focus)
        controls.addWidget(capture_btn)
        controls.addWidget(kdump_btn)
        controls.addWidget(rescan_btn)
        controls.addStretch()
        self.fix_detail = QTextBrowser()
        layout.addLayout(controls)
        layout.addWidget(self.fix_detail, 1)
        self.tabs.addTab(page, "Fix / next steps")

    def build_trends_tab(self) -> None:
        page = QWidget(); layout = QVBoxLayout(page)
        buttons = QHBoxLayout(); refresh = QPushButton("Refresh trends"); refresh.clicked.connect(self.refresh_trends)
        buttons.addWidget(refresh); buttons.addStretch(); layout.addLayout(buttons)
        self.trend_chart = TrendChart(); layout.addWidget(self.trend_chart)
        canary_title = QLabel("Current report: CPU, memory and I/O PSI pressure (avg10)")
        canary_title.setStyleSheet("font-weight: 650;")
        self.canary_chart = TrendChart()
        layout.addWidget(canary_title); layout.addWidget(self.canary_chart)
        self.trends_table = QTableWidget(0, 6)
        self.trends_table.setHorizontalHeaderLabels(["Date", "Mode", "Leading cause", "Critical", "Warnings", "Info"])
        self.trends_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.trends_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.trends_table, 1)
        self.canary_label = QLabel("Canary interpretation will appear after a scan.")
        self.canary_label.setWordWrap(True); layout.addWidget(self.canary_label)
        self.tabs.addTab(page, "Trends & heartbeat")

    def build_export_tab(self) -> None:
        page = QWidget(); layout = QVBoxLayout(page)
        self.privacy = QCheckBox("Redact username, hostname, email addresses and IP addresses")
        self.privacy.setChecked(True)
        html_btn = QPushButton("Export readable HTML")
        json_btn = QPushButton("Export complete JSON")
        text_btn = QPushButton("Export concise support text")
        folder_btn = QPushButton("Open reports folder")
        html_btn.clicked.connect(self.export_html); json_btn.clicked.connect(self.export_json); text_btn.clicked.connect(self.export_text)
        folder_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.report_dir))))
        for widget in (self.privacy, html_btn, json_btn, text_btn, folder_btn): layout.addWidget(widget)
        layout.addStretch(); self.tabs.addTab(page, "Export")

    def selected_finding(self) -> dict[str, Any] | None:
        row = self.findings_table.currentRow()
        if row < 0:
            return None
        item = self.findings_table.item(row, 0)
        return item.data(Qt.ItemDataRole.UserRole) if item else None

    def top_hypothesis(self) -> dict[str, Any] | None:
        items = self.report.get("hypotheses", []) if self.report else []
        return items[0] if items else None

    def show_fix_for_selection(self) -> None:
        self.fix_focus.setCurrentText("Selected finding")
        self.populate_fixes()
        self.tabs.setCurrentWidget(self.fix_detail.parentWidget())

    def populate_fixes(self) -> None:
        if not hasattr(self, "fix_detail"):
            return
        if not self.report:
            self.fix_detail.setHtml("<h2>No scan loaded</h2><p>Run a quick scan first.</p>")
            return
        choice = self.fix_focus.currentText()
        if choice == "Top likely cause":
            items = [self.top_hypothesis()] if self.top_hypothesis() else []
        elif choice == "All needs-attention items":
            items = [item for item in self.report.get("findings", []) if item.get("severity") in {"critical", "warning"}]
        else:
            items = [self.selected_finding()] if self.selected_finding() else []
        items = [item for item in items if item]
        if not items:
            self.fix_detail.setHtml("<h2>No item selected</h2><p>Select a finding or likely cause first.</p>")
            return
        self.fix_detail.setHtml("".join(self.fix_plan_html(item) for item in items))

    def fix_plan_html(self, item: dict[str, Any]) -> str:
        title = str(item.get("title", "Selected item"))
        category = str(item.get("category", ""))
        item_id = str(item.get("id", "")).lower()
        lower = f"{title} {category} {item_id}".lower()
        evidence = "".join(f"<li><code>{html.escape(str(line))}</code></li>" for line in item.get("evidence", [])[:6]) or "<li>No individual evidence line attached.</li>"
        if "intel" in lower or "display" in lower or "graphics" in lower or "kwin" in lower:
            steps = [
                "Update the graphics stack: sudo dnf upgrade --refresh kernel\\* mesa\\* plasma\\* kwin\\* kscreen\\* linux-firmware",
                "Reboot after the update: systemctl reboot",
                "Check whether firmware updates are available: fwupdmgr refresh --force && fwupdmgr get-updates",
                "Install firmware updates if any are listed: sudo fwupdmgr update",
                "Set one safe display mode in KDE: System Settings -> Display & Monitor -> choose one directly connected monitor -> Refresh rate 60 Hz -> disable HDR/adaptive sync/VRR if shown -> Apply.",
                "Temporarily unplug docks, adapters and extra monitors. Test the next call with one direct monitor only.",
                "After a stable call, reconnect one item at a time and run Quick scan after each change.",
                "If it still freezes, reboot and pick a different kernel from the GRUB Advanced options menu, then run Quick scan again.",
                "Open KDE System Log and search for: i915, drm, kwin, GPU HANG, reset, atomic update failure.",
            ]
            app_actions = "Use Enable evidence capture now, then Run quick scan after each display/configuration change."
        elif "pcie" in lower or "bus" in lower:
            steps = [
                "Find the device details: lspci -Dnnk | less",
                "Search the scan evidence for the PCI address shown in the warning, then match it to lspci output.",
                "Check firmware updates: fwupdmgr refresh --force && fwupdmgr get-updates",
                "Install firmware updates if any are listed: sudo fwupdmgr update",
                "If the device is Wi-Fi, test with Ethernet and temporarily disable Wi-Fi in KDE Network settings.",
                "Temporarily unplug USB-C docks, hubs, external GPUs and adapters, then run Full scan again.",
                "If it is a removable internal card, power off fully, reseat it, then test again.",
                "If the same PCIe address keeps recurring after firmware and reseating, replace or bypass that device/link.",
            ]
            app_actions = "Use Full scan after each hardware/configuration change to see whether the same PCIe address returns."
        elif "memory" in lower or "oom" in lower:
            steps = [
                "Check current memory: free -h",
                "List highest memory users: ps -eo pid,comm,%mem,%cpu --sort=-%mem | head -20",
                "Check swap: swapon --show",
                "Run Memtest readiness from Controlled tests, then reboot into Memtest from the boot menu when you can leave the machine alone.",
            ]
            app_actions = "Use Enable evidence capture and Verify Memtest boot entry."
        elif "thermal" in lower:
            steps = [
                "Watch temperatures live: sensors",
                "For continuous watching: watch -n 2 sensors",
                "Check recent thermal logs: journalctl -k --since '24 hours ago' | grep -iE 'thermal|throttl|overheat|critical temperature'",
                "Clean vents, verify fans are spinning, and keep the machine on a hard surface.",
                "Only run CPU stress from Controlled tests when interruption is acceptable.",
            ]
            app_actions = "Use Enable evidence capture before stress testing so the canary records temperatures."
        elif "storage" in lower or "smart" in lower or "btrfs" in lower:
            steps = [
                "Back up important files before running disk tests.",
                "List drives: lsblk -o NAME,PATH,TYPE,SIZE,MODEL,SERIAL,FSTYPE,MOUNTPOINTS",
                "Check SMART devices: sudo smartctl --scan-open",
                "View SMART health for a device: sudo smartctl -x /dev/nvme0n1",
                "For Btrfs status: sudo btrfs scrub status /",
                "Run Btrfs scrub only when disk activity is acceptable.",
            ]
            app_actions = "Use SMART short self-test or Btrfs scrub from Controlled tests after backing up."
        else:
            next_test = item.get("next_test", "")
            steps = [
                str(next_test) if next_test else "Enable evidence capture, reproduce once, then run another quick scan.",
                "Compare whether this item stays recurring, disappears, or is replaced by a more specific finding.",
            ]
            app_actions = "Use Enable evidence capture, Validate kdump, and Run quick scan after changes."
        steps_html = "".join(f"<li>{html.escape(step)}</li>" for step in steps)
        command_lines = [step for step in steps if any(token in step for token in ("sudo ", "dnf ", "fwupdmgr ", "systemctl ", "lspci ", "free ", "ps ", "swapon ", "sensors", "journalctl ", "lsblk ", "smartctl ", "btrfs ", "watch "))]
        commands_html = ""
        if command_lines:
            commands = "\n".join(line.split(": ", 1)[-1] for line in command_lines)
            commands_html = f"<h3>Commands</h3><pre>{html.escape(commands)}</pre>"
        return (
            f"<article><h2>{html.escape(title)}</h2>"
            f"<p><b>{html.escape(category or 'General')}</b> · {html.escape(str(item.get('confidence', 'unknown')))} confidence</p>"
            f"<h3>What to do next</h3><ol>{steps_html}</ol>"
            f"{commands_html}"
            f"<h3>App actions</h3><p>{html.escape(app_actions)}</p>"
            f"<h3>Evidence behind this plan</h3><ul>{evidence}</ul></article>"
        )

    def auth_changed(self, ready: bool) -> None:
        self.auth_badge.setText("🔓 Authorised for this app session" if ready else "🔒 Authorisation not started")
        self.auth_badge.setStyleSheet(
            "padding: 7px 10px; border: 1px solid #12b76a; border-radius: 8px;" if ready
            else "padding: 7px 10px; border: 1px solid #d0d5dd; border-radius: 8px;"
        )

    def set_status(self, text: str) -> None:
        self.status.setText(text)

    def set_busy(self, busy: bool, label: str = "") -> None:
        self.busy = busy
        for button in (self.quick_btn, self.full_btn, self.capture_btn, self.tools_btn):
            button.setEnabled(not busy)
        self.cancel_btn.setEnabled(busy)
        self.progress.setVisible(busy)
        if not busy:
            self.progress.setValue(0)
        if label:
            self.set_status(label)

    def progress_update(self, current: int, total: int, label: str) -> None:
        percent = int(current * 100 / total) if total else 0
        self.progress.setRange(0, 100); self.progress.setValue(percent)
        self.set_status(f"{label} — {current}/{total}")

    def cancel_action(self) -> None:
        if QMessageBox.question(self, "Cancel?", "Cancel the current privileged action? The helper will close and the next action will ask for authorisation again.") == QMessageBox.StandardButton.Yes:
            self.broker.cancel_all(); self.set_busy(False, "Cancelled.")

    def run_scan(self, mode: str) -> None:
        self.set_busy(True, f"Starting {mode} scan…")
        self.broker.request("scan", {"mode": mode}, self.scan_finished, self.progress_update)

    def scan_finished(self, ok: bool, data: Any) -> None:
        self.set_busy(False)
        if not ok:
            if str(data) != "Cancelled.":
                QMessageBox.warning(self, "Scan failed", str(data))
            self.set_status("Scan cancelled." if str(data) == "Cancelled." else "Scan did not complete.")
            return
        self.report = data
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        path = self.report_dir / f"scan-{stamp}.json"
        path.write_text(json.dumps(self.report, indent=2, ensure_ascii=False))
        self.load_report()
        self.set_status(f"Scan complete and saved to {path}")
        self.refresh_capture_status(silent=True)

    def load_report(self) -> None:
        if not self.report: return
        overall = self.report.get("overall", {})
        self.overall_title.setText(overall.get("title", "No leading cause identified"))
        self.overall_summary.setText(overall.get("summary", ""))
        for category, card in self.cards.items():
            state = self.report.get("categories", {}).get(category, {"status": "not_checked", "label": "Not checked"})
            card.set_state(state.get("label", "Not checked"), state.get("status", "not_checked"))
        self.populate_findings(); self.populate_hypotheses(); self.populate_timeline(); self.populate_checks(); self.populate_fixes()
        canary = self.report.get("canary", {})
        self.canary_label.setText(canary.get("interpretation", "No canary interpretation."))
        samples = canary.get("samples", [])[-120:]
        self.canary_chart.set_series([
            ("CPU PSI", [float(x.get("psi_cpu_some_avg10", 0) or 0) for x in samples], QColor("#7f56d9")),
            ("Memory PSI", [float(x.get("psi_memory_some_avg10", 0) or 0) for x in samples], QColor("#d92d20")),
            ("I/O PSI", [float(x.get("psi_io_some_avg10", 0) or 0) for x in samples], QColor("#1570ef")),
        ])
        self.smart_device.clear(); self.smart_device.addItems(self.report.get("test_targets", {}).get("smart_devices", []))
        self.refresh_trends()

    def filtered_findings(self) -> list[dict[str, Any]]:
        if not self.report: return []
        items = self.report.get("findings", [])
        choice = self.finding_filter.currentText()
        if choice == "This incident": return [f for f in items if f.get("scope") == "this_incident"]
        if choice == "New": return [f for f in items if f.get("status") == "new"]
        if choice == "Recurring": return [f for f in items if f.get("status") == "recurring"]
        if choice == "Warnings and critical only": return [f for f in items if f.get("severity") in {"warning", "critical"}]
        return items

    def populate_findings(self) -> None:
        items = self.filtered_findings(); self.findings_table.setRowCount(len(items))
        for row, item in enumerate(items):
            values = [
                f"{SEVERITY_ICON.get(item.get('severity'), '')} {item.get('severity','').title()}",
                "This crash" if item.get("scope") == "this_incident" else "Historical",
                STATUS_ICON.get(item.get("status"), item.get("status", "")),
                item.get("category", ""), item.get("title", ""), item.get("confidence", ""),
            ]
            for col, value in enumerate(values): self.findings_table.setItem(row, col, QTableWidgetItem(str(value)))
            self.findings_table.item(row, 0).setData(Qt.ItemDataRole.UserRole, item)
        if items: self.findings_table.selectRow(0)
        else: self.finding_detail.setHtml("<p>No findings match this filter.</p>")

    def show_finding(self) -> None:
        row = self.findings_table.currentRow()
        if row < 0: return
        item = self.findings_table.item(row, 0).data(Qt.ItemDataRole.UserRole)
        evidence = "".join(f"<li><code>{html.escape(line)}</code></li>" for line in item.get("evidence", [])) or "<li>No individual line attached.</li>"
        self.finding_detail.setHtml(
            f"<h2>{html.escape(item.get('title',''))}</h2><p><b>{item.get('severity','').upper()}</b> · {html.escape(item.get('category',''))} · {html.escape(item.get('confidence',''))} confidence</p>"
            f"<p>{html.escape(item.get('explanation',''))}</p><h3>Evidence</h3><ul>{evidence}</ul>"
        )
        if self.fix_focus.currentText() == "Selected finding":
            self.populate_fixes()

    def populate_hypotheses(self) -> None:
        items = self.report.get("hypotheses", []) if self.report else []
        self.hyp_table.setRowCount(len(items))
        for row, item in enumerate(items):
            values = [item.get("rank"), item.get("confidence"), item.get("score"), item.get("category"), item.get("title")]
            for col, value in enumerate(values): self.hyp_table.setItem(row, col, QTableWidgetItem(str(value)))
            self.hyp_table.item(row, 0).setData(Qt.ItemDataRole.UserRole, item)
        if items: self.hyp_table.selectRow(0)

    def show_hypothesis(self) -> None:
        row = self.hyp_table.currentRow()
        if row < 0: return
        item = self.hyp_table.item(row, 0).data(Qt.ItemDataRole.UserRole)
        bullets = lambda values: "".join(f"<li>{html.escape(str(value))}</li>" for value in values) or "<li>None recorded.</li>"
        self.hyp_detail.setHtml(
            f"<h2>#{html.escape(str(item.get('rank', '')))} — {html.escape(str(item.get('title', 'Untitled hypothesis')))}</h2>"
            f"<p><b>{html.escape(str(item.get('confidence', 'unknown')).title())} confidence</b> · score {html.escape(str(item.get('score', '')))}</p>"
            f"<h3>Evidence for</h3><ul>{bullets(item.get('supports', []))}</ul>"
            f"<h3>Evidence against / uncertainty</h3><ul>{bullets(item.get('against', []))}</ul>"
            f"<h3>Best next test</h3><p>{html.escape(item.get('next_test',''))}</p>"
            f"<h3>Would strengthen it</h3><p>{html.escape(item.get('would_confirm',''))}</p>"
            f"<h3>Would weaken it</h3><p>{html.escape(item.get('would_weaken',''))}</p>"
        )
        if self.fix_focus.currentText() == "Top likely cause":
            self.populate_fixes()

    def populate_timeline(self) -> None:
        items = self.report.get("timeline", []) if self.report else []
        self.timeline_table.setRowCount(len(items))
        for row, item in enumerate(items):
            values = [item.get("timestamp"), item.get("proximity"), item.get("category"), item.get("summary")]
            for col, value in enumerate(values): self.timeline_table.setItem(row, col, QTableWidgetItem(str(value)))
            self.timeline_table.item(row, 0).setData(Qt.ItemDataRole.UserRole, item)
        if items: self.timeline_table.selectRow(max(0, len(items) - 1))

    def show_timeline(self) -> None:
        row = self.timeline_table.currentRow()
        if row < 0: return
        item = self.timeline_table.item(row, 0).data(Qt.ItemDataRole.UserRole)
        self.timeline_detail.setPlainText(f"{item.get('timestamp')}\n{item.get('proximity')}\n{item.get('category')}\n\n{item.get('evidence')}")

    def populate_checks(self) -> None:
        checks = list(self.report.get("checks", {}).items()) if self.report else []
        self.checks_table.setRowCount(len(checks))
        for row, (key, item) in enumerate(checks):
            values = [item.get("category", ""), item.get("title", key), item.get("status", ""), f"{item.get('duration_seconds',0)} s"]
            for col, value in enumerate(values): self.checks_table.setItem(row, col, QTableWidgetItem(str(value)))
            self.checks_table.item(row, 0).setData(Qt.ItemDataRole.UserRole, (key, item))
        if checks: self.checks_table.selectRow(0)

    def show_check(self) -> None:
        row = self.checks_table.currentRow()
        if row < 0: return
        key, item = self.checks_table.item(row, 0).data(Qt.ItemDataRole.UserRole)
        self.check_output.setPlainText(
            f"{item.get('title',key)}\nCategory: {item.get('category','')}\nStatus: {item.get('status')} (return {item.get('returncode')})\nCommand: {item.get('command')}\n\n{item.get('output','')}"
        )

    def enable_capture(self) -> None:
        dialog = CaptureDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted: return
        self.set_busy(True, "Enabling crash capture…")
        self.broker.request("setup_capture", {"cockpit": dialog.cockpit.isChecked()}, self.capture_setup_done, self.progress_update)

    def capture_setup_done(self, ok: bool, data: Any) -> None:
        self.set_busy(False)
        if not ok: QMessageBox.warning(self, "Capture setup failed", str(data)); return
        text = json.dumps(data, indent=2)
        self.capture_output.setPlainText(text)
        QMessageBox.information(self, "Crash capture configured", "Crash capture was configured. Reboot before relying on kdump or the desktop heartbeat.")
        self.refresh_capture_status(silent=True)

    def refresh_capture_status(self, silent: bool = False) -> None:
        if not silent: self.set_busy(True, "Checking capture readiness…")
        self.broker.request("capture_status", {}, lambda ok, data: self.capture_status_done(ok, data, silent))

    def capture_status_done(self, ok: bool, data: Any, silent: bool) -> None:
        if not silent: self.set_busy(False)
        if not ok:
            if not silent: QMessageBox.warning(self, "Status failed", str(data))
            return
        self.capture_output.setPlainText(json.dumps(data, indent=2))

    def validate_kdump(self) -> None:
        self.set_busy(True, "Validating kdump without forcing a crash…")
        self.broker.request("kdump_validate", {}, self.test_done)

    def install_tools(self) -> None:
        if QMessageBox.question(self, "Install diagnostic tools?", "Install or repair the fixed Fedora diagnostic package set? Cockpit is not included.") != QMessageBox.StandardButton.Yes: return
        self.set_busy(True, "Installing diagnostic tools…")
        self.broker.request("install_tools", {}, self.tools_done, self.progress_update)

    def tools_done(self, ok: bool, data: Any) -> None:
        self.set_busy(False); self.test_output.setPlainText(json.dumps(data, indent=2) if not isinstance(data, str) else data)
        if not ok: QMessageBox.warning(self, "Tool installation failed", str(data))
        else: QMessageBox.information(self, "Tools", "Diagnostic tool installation finished. Optional unavailable packages are listed in the output.")

    def install_cockpit(self) -> None:
        if QMessageBox.question(self, "Install or open Cockpit?", "Install any missing Cockpit packages, enable its local web interface on port 9090, then open it? This is optional and separate from crash capture.") != QMessageBox.StandardButton.Yes: return
        self.set_busy(True, "Installing optional Cockpit components…")
        self.broker.request("install_cockpit", {}, self.cockpit_done, self.progress_update)

    def cockpit_done(self, ok: bool, data: Any) -> None:
        self.set_busy(False); self.capture_output.setPlainText(json.dumps(data, indent=2) if not isinstance(data, str) else data)
        if ok: QDesktopServices.openUrl(QUrl("https://localhost:9090"))
        else: QMessageBox.warning(self, "Cockpit installation failed", str(data))

    def smart_test(self) -> None:
        device = self.smart_device.currentText()
        if not device:
            QMessageBox.information(self, "No drive", "Run a scan first so SMART-capable drives can be discovered."); return
        self.run_test("smart_short", {"device": device}, f"Start the drive's built-in SMART short test on {device}?", True)

    def run_test(self, action: str, params: dict[str, Any], question: str, disruptive: bool) -> None:
        if QMessageBox.question(self, "Confirm controlled test", question) != QMessageBox.StandardButton.Yes: return
        if disruptive:
            phrase = action.replace("_", " ")
            typed, ok = QInputDialog.getText(
                self,
                "Type to confirm",
                f"Type {phrase} to start this disruptive action.",
            )
            if not ok or typed.strip().lower() != phrase:
                self.set_status("Controlled action cancelled.")
                return
        self.set_busy(True, f"Running {action.replace('_',' ')}…")
        self.broker.request(action, params, self.test_done, self.progress_update)

    def test_done(self, ok: bool, data: Any) -> None:
        self.set_busy(False)
        text = json.dumps(data, indent=2) if isinstance(data, (dict, list)) else str(data)
        self.test_output.setPlainText(text); self.capture_output.setPlainText(text)
        if not ok and text != "Cancelled.":
            QMessageBox.warning(self, "Action failed", text)
        elif ok:
            self.set_status("Controlled action completed. Review the output before drawing conclusions.")

    def launch(self, argv: list[str]) -> None:
        if not shutil.which(argv[0]):
            QMessageBox.information(self, "Not installed", f"{argv[0]} is not installed. Use Install/repair tools."); return
        subprocess.Popen(argv, start_new_session=True)

    def load_pending_autoscan(self) -> None:
        path = Path(f"/var/lib/fedora-crash-doctor/autoscans/{os.getuid()}/latest.json")
        if not path.exists(): return
        try:
            data = json.loads(path.read_text())
            saved = self.report_dir / f"scan-autoscan-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
            saved.write_text(json.dumps(data, indent=2, ensure_ascii=False))
            path.unlink(missing_ok=True)
            self.report = data; self.load_report()
            counts = data.get("counts", {})
            QMessageBox.information(self, "Crash autoscan loaded", f"An automatic post-crash scan was found: {counts.get('critical',0)} critical, {counts.get('warning',0)} warnings.")
        except Exception as exc:
            self.set_status(f"Could not load pending autoscan: {exc}")

    def refresh_trends(self) -> None:
        rows = []
        for path in sorted(self.report_dir.glob("scan-*.json")):
            try:
                data = json.loads(path.read_text())
            except Exception:
                continue
            rows.append(data)
        self.trends_table.setRowCount(len(rows))
        critical, warning, info = [], [], []
        for row, data in enumerate(rows):
            meta, counts = data.get("metadata", {}), data.get("counts", {})
            values = [meta.get("generated", ""), meta.get("mode", ""), data.get("overall", {}).get("title", ""), counts.get("critical", 0), counts.get("warning", 0), counts.get("info", 0)]
            for col, value in enumerate(values): self.trends_table.setItem(row, col, QTableWidgetItem(str(value)))
            critical.append(float(counts.get("critical", 0))); warning.append(float(counts.get("warning", 0))); info.append(float(counts.get("info", 0)))
        self.trend_chart.set_series([
            ("Critical", critical, QColor("#b42318")), ("Warnings", warning, QColor("#d97706")), ("Info", info, QColor("#2563eb")),
        ])

    def redact(self, text: str) -> str:
        if not self.privacy.isChecked(): return text
        user, host = os.environ.get("USER", ""), socket.gethostname()
        for old, new in ((f"/home/{user}", "/home/REDACTED-USER"), (host, "REDACTED-HOST"), (user, "REDACTED-USER")):
            if old: text = text.replace(old, new)
        text = re.sub(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "REDACTED-EMAIL", text)
        text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "REDACTED-IP", text)
        return text

    def choose_export(self, suffix: str, label: str) -> str:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        path, _ = QFileDialog.getSaveFileName(self, label, str(self.report_dir / f"fedora-crash-doctor-{stamp}.{suffix}"), f"{suffix.upper()} (*.{suffix})")
        return path

    def export_json(self) -> None:
        if not self.report: QMessageBox.information(self, "No report", "Run a scan first."); return
        path = self.choose_export("json", "Export JSON")
        if path: Path(path).write_text(self.redact(json.dumps(self.report, indent=2, ensure_ascii=False)))

    def export_text(self) -> None:
        if not self.report: QMessageBox.information(self, "No report", "Run a scan first."); return
        path = self.choose_export("txt", "Export support text")
        if not path: return
        lines = [
            "FEDORA CRASH DOCTOR", "=" * 22,
            self.report.get("overall", {}).get("summary", ""), "", "RANKED CAUSES",
        ]
        for item in self.report.get("hypotheses", [])[:5]:
            lines.extend([
                f"{item.get('rank', '')}. {item.get('title', 'Untitled hypothesis')} — {item.get('confidence', 'unknown')} ({item.get('score', '')})",
                f"   Next test: {item.get('next_test', '')}",
            ])
        lines.extend(["", "FINDINGS"])
        for item in self.report.get("findings", []):
            lines.append(
                f"[{str(item.get('severity', '')).upper()}] [{item.get('scope', '')}] "
                f"{item.get('title', 'Untitled finding')}: {item.get('explanation', '')}"
            )
            for evidence in item.get("evidence", [])[:4]: lines.append(f"  - {evidence}")
        lines.extend(["", "TIMELINE"])
        for item in self.report.get("timeline", [])[-20:]:
            lines.append(f"{item.get('timestamp', '')} | {item.get('proximity', '')} | {item.get('summary', '')}")
        Path(path).write_text(self.redact("\n".join(lines)))

    def export_html(self) -> None:
        if not self.report: QMessageBox.information(self, "No report", "Run a scan first."); return
        path = self.choose_export("html", "Export HTML")
        if not path: return
        report = self.report
        hypotheses = "".join(
            f"<article><h3>#{html.escape(str(h.get('rank', '')))} {html.escape(str(h.get('title', 'Untitled hypothesis')))}</h3>"
            f"<p><b>{html.escape(str(h.get('confidence', 'unknown')))} confidence; score {html.escape(str(h.get('score', '')))}</b></p>"
            f"<p>{html.escape(str(h.get('next_test', '')))}</p></article>" for h in report.get("hypotheses", [])
        )
        findings = "".join(
            f"<article class='{html.escape(str(f.get('severity', 'info')))}'><h3>{html.escape(str(f.get('title', 'Untitled finding')))}</h3>"
            f"<p>{html.escape(str(f.get('explanation', '')))}</p>"
            f"<pre>{html.escape(chr(10).join(f.get('evidence', [])))}</pre></article>" for f in report.get("findings", [])
        )
        timeline = "".join(
            f"<tr><td>{html.escape(str(t.get('timestamp', '')))}</td><td>{html.escape(str(t.get('proximity', '')))}</td>"
            f"<td>{html.escape(str(t.get('summary', '')))}</td></tr>" for t in report.get("timeline", [])
        )
        document = f"""<!doctype html><html><head><meta charset='utf-8'><title>Fedora Crash Doctor</title><style>
body{{font-family:system-ui;max-width:1180px;margin:30px auto;padding:0 18px;background:#f6f7f9;color:#1d2939}}header,article,.panel{{background:white;border:1px solid #d0d5dd;border-radius:12px;padding:18px;margin:12px 0}}.critical{{border-left:7px solid #b42318}}.warning{{border-left:7px solid #d97706}}.info{{border-left:7px solid #2563eb}}pre{{white-space:pre-wrap;background:#f2f4f7;padding:10px}}table{{width:100%;border-collapse:collapse;background:white}}td,th{{padding:8px;border:1px solid #d0d5dd;text-align:left}}</style></head><body>
<header><h1>Fedora Crash Doctor</h1><h2>{html.escape(report.get('overall',{}).get('title',''))}</h2><p>{html.escape(report.get('overall',{}).get('summary',''))}</p></header>
<h2>Ranked causes</h2>{hypotheses}<h2>Findings</h2>{findings}<h2>Incident timeline</h2><table><tr><th>Time</th><th>Proximity</th><th>Event</th></tr>{timeline}</table></body></html>"""
        Path(path).write_text(self.redact(document)); QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    def closeEvent(self, event) -> None:
        if self.broker.ready: self.broker.cancel_all()
        super().closeEvent(event)


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("Fedora Crash Doctor")
    app.setOrganizationName("Fedora Crash Doctor")
    window = MainWindow(); window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
