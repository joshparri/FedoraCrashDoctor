"""Job-lifecycle tests for the explicit symbolic-backtrace action.

symbolic_analysis.start_symbolic_analysis() is the only supported way to run
GDB/debuginfod -- these tests cover its state machine (queued/running/
completed/unavailable/cancelled), deduplication, and real cancellation of a
running debugger process, independent of app_crash_doctor's log parsing.
"""
from __future__ import annotations

import os
import time

import pytest

import symbolic_analysis


@pytest.fixture(autouse=True)
def _clean_registry():
    symbolic_analysis._reset_registry_for_tests()
    yield
    symbolic_analysis._reset_registry_for_tests()


def _fake_debugger(tmp_path, monkeypatch, body):
    binary = tmp_path / 'coredumpctl'
    binary.write_text('#!/usr/bin/python3\n' + body)
    binary.chmod(0o700)
    # gdb only needs to exist on PATH for tooling_available()'s check;
    # coredumpctl (faked above) is what generate_backtrace() actually execs.
    gdb_stub = tmp_path / 'gdb'
    gdb_stub.write_text('#!/usr/bin/python3\n')
    gdb_stub.chmod(0o700)
    monkeypatch.setenv('PATH', str(tmp_path) + os.pathsep + os.environ['PATH'])
    directory = tmp_path / 'traces'
    directory.mkdir(mode=0o700)
    return directory


def test_unavailable_when_tooling_missing(monkeypatch):
    monkeypatch.setattr(symbolic_analysis.shutil, 'which', lambda name: None)
    job = symbolic_analysis.start_symbolic_analysis('1', '/bin/app', '100')
    assert job.state == 'unavailable'
    assert job.result['state'] == 'unavailable'
    # No process/thread should have been left running for an unavailable job.
    assert job._thread is None


def test_successful_job_reaches_completed(tmp_path, monkeypatch):
    directory = _fake_debugger(tmp_path, monkeypatch, "print('resolved frame')")
    job = symbolic_analysis.start_symbolic_analysis('123', '/usr/bin/example', '100',
                                                      output_dir=directory)
    job.join(timeout=5)
    assert job.state == 'completed'
    assert job.result['state'] == 'completed'


def test_default_job_does_not_use_network(tmp_path, monkeypatch):
    """start_symbolic_analysis() without allow_network=True must never enable
    debuginfod -- network access is opt-in, not a side effect of starting a
    job at all."""
    seen_path = tmp_path / 'seen_env.json'
    directory = _fake_debugger(tmp_path, monkeypatch, f'''import sys, os, json
open({str(seen_path)!r}, 'w').write(json.dumps({{'url_present': 'DEBUGINFOD_URLS' in os.environ,
                                                  'args': sys.argv[1:]}}))
''')
    job = symbolic_analysis.start_symbolic_analysis('1', '/bin/app', '100', output_dir=directory)
    job.join(timeout=5)
    assert job.allow_network is False
    assert job.result['network_used'] is False

    import json
    seen = json.loads(seen_path.read_text())
    assert seen['url_present'] is False
    assert 'set debuginfod enabled on' not in seen['args'][3]


def test_explicit_allow_network_enables_debuginfod(tmp_path, monkeypatch):
    directory = _fake_debugger(tmp_path, monkeypatch, "print('ok')")
    job = symbolic_analysis.start_symbolic_analysis('2', '/bin/app', '100', output_dir=directory,
                                                      allow_network=True)
    job.join(timeout=5)
    assert job.allow_network is True
    assert job.result['network_used'] is True


def test_dedup_returns_same_job_unless_forced(tmp_path, monkeypatch):
    directory = _fake_debugger(tmp_path, monkeypatch, "import time\ntime.sleep(0.3)")
    job1 = symbolic_analysis.start_symbolic_analysis('1', '/bin/app', '100', output_dir=directory)
    job2 = symbolic_analysis.start_symbolic_analysis('1', '/bin/app', '100', output_dir=directory)
    assert job1 is job2
    job1.join(timeout=5)

    job3 = symbolic_analysis.start_symbolic_analysis('1', '/bin/app', '100',
                                                       output_dir=directory, force=True)
    assert job3 is not job1
    job3.join(timeout=5)


def test_cancel_stops_a_running_job_and_kills_the_process(tmp_path, monkeypatch):
    directory = _fake_debugger(tmp_path, monkeypatch,
                                "import time\nwhile True:\n print('x', flush=True)\n time.sleep(0.02)")
    job = symbolic_analysis.start_symbolic_analysis('1', '/bin/app', '100',
                                                      output_dir=directory, timeout=30)
    # Let it actually start running before cancelling.
    for _ in range(100):
        if job.state == 'running':
            break
        time.sleep(0.01)
    assert job.state == 'running'

    job.cancel()
    job.join(timeout=5)
    assert job.state == 'cancelled'
    assert job.result['state'] == 'cancelled'


def test_get_job_returns_the_started_job(tmp_path, monkeypatch):
    directory = _fake_debugger(tmp_path, monkeypatch, "print('ok')")
    job = symbolic_analysis.start_symbolic_analysis('7', '/bin/app', '200', output_dir=directory)
    assert symbolic_analysis.get_job('7', '200') is job
    assert symbolic_analysis.get_job('missing', '0') is None
