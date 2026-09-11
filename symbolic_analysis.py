"""Explicit, bounded symbolic-backtrace jobs.

app_crash_doctor.generate_backtrace() launches GDB via coredumpctl. That must
never happen as a side effect of parsing a log or running a normal scan --
it can create large files, and with debuginfod enabled it is also real
network activity. This module is the only supported way to actually run it:
start_symbolic_analysis() is an explicit action (e.g. a GUI "Analyse
coredump with symbols" button) that returns a job object with an
inspectable lifecycle instead of a fire-and-forget thread.

Network access is opt-in and explicit, not a side effect of starting a job.
allow_network defaults to False, meaning symbolication only uses debug info
already present on the machine and debuginfod is explicitly turned off (see
generate_backtrace's docstring for how that is enforced against inherited
environment). Pass allow_network=True only from a caller whose UI has told
the user that Fedora's debuginfod service may be contacted to download
symbols over the network -- e.g. a distinct "include network symbols"
checkbox/confirmation on the "Analyse coredump with symbols" action, not a
default. Each job's result records which mode actually ran
(result['network_used']), so a caller never has to guess after the fact.

Job states: queued, running, completed, failed, timed_out, truncated,
cancelled, unavailable. The first five/six come from generate_backtrace()
itself; 'unavailable' is returned immediately, with no process ever started,
when gdb or coredumpctl are not installed.
"""
from __future__ import annotations

import shutil
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from app_crash_doctor import generate_backtrace

TERMINAL_STATES = frozenset({
    "completed", "failed", "timed_out", "truncated", "cancelled", "unavailable",
})

_registry_lock = threading.Lock()
_registry: dict[tuple[str, str], "SymbolicAnalysisJob"] = {}


def tooling_available() -> bool:
    """Whether gdb and coredumpctl are both installed.

    Both are Recommends, not Requires, in the RPM: a system without them is
    a normal, supported configuration. Callers should show 'unavailable'
    rather than attempting analysis and getting a confusing generic failure.
    """
    return shutil.which("gdb") is not None and shutil.which("coredumpctl") is not None


@dataclass
class SymbolicAnalysisJob:
    pid: str
    executable: str
    timestamp: str
    allow_network: bool = False
    state: str = "queued"
    result: dict[str, Any] | None = None
    created_at: float = field(default_factory=time.monotonic)
    _cancel_event: threading.Event = field(default_factory=threading.Event, repr=False, compare=False)
    _thread: "threading.Thread | None" = field(default=None, repr=False, compare=False)

    def is_done(self) -> bool:
        return self.state in TERMINAL_STATES

    def cancel(self) -> None:
        """Request cancellation. The debugger process tree is still killed
        via generate_backtrace()'s own cleanup path; this just stops it
        early instead of waiting for the timeout."""
        self._cancel_event.set()

    def join(self, timeout: float | None = None) -> None:
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    def _run(self, **kwargs: Any) -> None:
        self.state = "running"
        outcome = generate_backtrace(
            self.pid, self.executable, self.timestamp,
            cancel_event=self._cancel_event, allow_network=self.allow_network, **kwargs,
        )
        self.result = outcome
        self.state = outcome.get("state", "failed")


def start_symbolic_analysis(pid: str, executable: str, timestamp: str, *,
                             allow_network: bool = False, force: bool = False,
                             **kwargs: Any) -> SymbolicAnalysisJob:
    """Start (or, unless force=True, reuse) a bounded symbolic-backtrace job
    for one (pid, timestamp) crash identity. This is the explicit action a
    caller invokes on the user's behalf -- never call it from analysis code
    that runs automatically.

    allow_network defaults to False (local debug info only, debuginfod
    disabled). Only pass allow_network=True from a caller whose UI has told
    the user that Fedora's debuginfod service may be contacted over the
    network to fetch symbols -- see this module's docstring."""
    key = (str(pid), str(timestamp))
    with _registry_lock:
        existing = _registry.get(key)
        if existing is not None and not force:
            return existing

        if not tooling_available():
            job = SymbolicAnalysisJob(
                pid=str(pid), executable=executable, timestamp=str(timestamp),
                allow_network=allow_network, state="unavailable",
                result={"state": "unavailable", "error": "gdb/coredumpctl not installed",
                        "network_used": False},
            )
            _registry[key] = job
            return job

        job = SymbolicAnalysisJob(pid=str(pid), executable=executable, timestamp=str(timestamp),
                                   allow_network=allow_network)
        thread = threading.Thread(target=job._run, kwargs=kwargs, daemon=True)
        job._thread = thread
        _registry[key] = job

    thread.start()
    return job


def get_job(pid: str, timestamp: str) -> "SymbolicAnalysisJob | None":
    return _registry.get((str(pid), str(timestamp)))


def _reset_registry_for_tests() -> None:
    with _registry_lock:
        _registry.clear()
