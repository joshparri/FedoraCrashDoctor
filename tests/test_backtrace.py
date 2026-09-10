"""Exercise the real wrapper against a fake debugger, without reading host cores."""
import os
import stat
import time
from pathlib import Path

from app_crash_doctor import generate_backtrace


def fake_debugger(tmp_path, monkeypatch, body):
    binary = tmp_path / 'coredumpctl'
    binary.write_text('#!/usr/bin/python3\n' + body)
    binary.chmod(0o700)
    monkeypatch.setenv('PATH', str(tmp_path) + os.pathsep + os.environ['PATH'])
    directory = tmp_path / 'traces'
    directory.mkdir(mode=0o700)
    return directory


def test_backtrace_command_limits_and_private_output(tmp_path, monkeypatch):
    directory = fake_debugger(tmp_path, monkeypatch, '''import sys, os, resource, json
print(json.dumps({'args': sys.argv[1:], 'url': os.environ['DEBUGINFOD_URLS'],
                  'memory': resource.getrlimit(resource.RLIMIT_AS)[0]}))
''')
    result = generate_backtrace('123', '/usr/bin/example', '100', output_dir=directory)
    assert result['state'] == 'completed'
    import json
    output = json.loads(Path(result['path']).read_text().split('\n', 1)[1])
    assert output['args'][:3] == ['debug', '123', 'COREDUMP_EXE=/usr/bin/example']
    assert output['args'][3].startswith('--debugger-arguments=--batch')
    assert 'set debuginfod enabled on' in output['args'][3]
    assert output['memory'] == 1024 ** 3
    assert output['url'] == 'https://debuginfod.fedoraproject.org/'
    assert stat.S_IMODE(Path(result['path']).stat().st_mode) == 0o600


def test_chatty_process_has_absolute_deadline(tmp_path, monkeypatch):
    directory = fake_debugger(tmp_path, monkeypatch, '''import time
while True:
 print('progress', flush=True)
 time.sleep(0.02)
''')
    start = time.monotonic()
    result = generate_backtrace('123', '/bin/app', '100', output_dir=directory, timeout=0.3)
    assert result['state'] == 'timed_out'
    assert time.monotonic() - start < 3


def test_output_bound(tmp_path, monkeypatch):
    directory = fake_debugger(tmp_path, monkeypatch, "print('x' * 100000)")
    result = generate_backtrace('123', '/bin/app', '100', output_dir=directory, output_limit=1024)
    assert result['state'] == 'truncated'
    assert Path(result['path']).stat().st_size == 1024


def test_rejects_symlink_directory_and_public_directory(tmp_path):
    target = tmp_path / 'target'
    target.mkdir(mode=0o700)
    link = tmp_path / 'link'
    link.symlink_to(target)
    assert generate_backtrace('1', '/bin/app', '1', output_dir=link)['state'] == 'failed'
    target.chmod(0o755)
    assert generate_backtrace('1', '/bin/app', '1', output_dir=target)['state'] == 'failed'
    assert not list(target.iterdir())


def test_debugger_failure_is_not_success(tmp_path, monkeypatch):
    directory = fake_debugger(tmp_path, monkeypatch, 'raise SystemExit(2)')
    assert generate_backtrace('1', '/bin/app', '1', output_dir=directory)['state'] == 'failed'


def test_default_ten_mib_bound(tmp_path, monkeypatch):
    directory = fake_debugger(tmp_path, monkeypatch, "import os\nos.write(1, b'x' * (11 * 1024 * 1024))")
    result = generate_backtrace('1', '/bin/app', '1', output_dir=directory)
    assert result['state'] == 'truncated'
    assert Path(result['path']).stat().st_size == 10 * 1024 * 1024


def test_timeout_kills_descendants(tmp_path, monkeypatch):
    directory = fake_debugger(tmp_path, monkeypatch, "import subprocess, time\np = subprocess.Popen(['/usr/bin/sleep', '30'])\nprint(p.pid, flush=True)\ntime.sleep(30)")
    result = generate_backtrace('1', '/bin/app', '1', output_dir=directory, timeout=0.5)
    assert result['state'] == 'timed_out'
    child = int(Path(result['path']).read_text().splitlines()[1])
    for _ in range(100):
        status = Path(f'/proc/{child}/stat')
        try:
            state = status.read_text().split()[2]
        except FileNotFoundError:
            break  # The kernel reaped the child between observations.
        if state == 'Z':
            break
        time.sleep(0.01)
    else:
        raise AssertionError('Debugger descendant remains running')


def test_async_result_is_reported(monkeypatch):
    import app_crash_doctor
    import threading
    threads = []
    real_thread = threading.Thread
    def record_thread(*args, **kwargs):
        thread = real_thread(*args, **kwargs)
        threads.append(thread)
        return thread
    monkeypatch.setattr(threading, 'Thread', record_thread)
    monkeypatch.setattr(app_crash_doctor, 'generate_backtrace', lambda *args: {'state': 'completed', 'path': '/private/trace.txt'})
    lines = [f'Thu 2026-09-10 10:32:0{i} AEST {i+1} 1002 1002 SIGABRT present /bin/probe 19K' for i in range(3)]
    issues = app_crash_doctor.analyze_app_crashes(lines)
    for thread in threads:
        thread.join(timeout=2)
    assert issues[0]['backtrace'] == {'state': 'completed', 'path': '/private/trace.txt'}
