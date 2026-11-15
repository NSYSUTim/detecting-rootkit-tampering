"""Capture a subprocess result and its CPU, elapsed-time and memory measurements."""
import json
import os
import signal
import subprocess
import time

def execute(command, output, tag, env=None, stdin=None):
    metrics = output / (tag + '.time')
    start = time.monotonic_ns()
    stdout_path = output / (tag + '.stdout')
    stderr_path = output / (tag + '.stderr')
    timeout = False
    with stdout_path.open('x') as stdout, stderr_path.open('x') as stderr:
        process = subprocess.Popen(['/usr/bin/time', '-o', str(metrics), '-f', '%e,%U,%S,%M', *command], stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, text=True, env=env, start_new_session=True)
        try:
            process.wait(timeout=90)
        except subprocess.TimeoutExpired:
            timeout = True
            os.killpg(process.pid, signal.SIGQUIT if '--cells' in command else signal.SIGTERM)
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
    elapsed = time.monotonic_ns() - start
    result = {'returncode': process.returncode, 'wall_ns': elapsed, 'command': command, 'timeout': timeout}
    try:
        lines = metrics.read_text().splitlines()
        values = lines[-1].split(',')
        result.update(time_seconds=float(values[0]), user_seconds=float(values[1]), system_seconds=float(values[2]), maxrss_kib=int(values[3]))
    except (ValueError, IndexError, OSError):
        result['metrics_error'] = True
    try:
        result['result'] = json.loads(stdout_path.read_text())
    except ValueError:
        result['json_error'] = True
    return result
