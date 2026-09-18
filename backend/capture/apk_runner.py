"""
Run the APK examination engine as a separate process and read its report.

See apk_engine/__init__.py for why it is a separate program. This module is the
whole boundary: a path goes out on the command line, a JSON report comes back on
stdout, and nothing else crosses — not Django settings, not the database
credentials, not SECRET_KEY. The process examining a hostile sample is given
PATH, PYTHONPATH and a locale, and that is all.

Every way the process can fail — timeout, memory limit, crash, output that is
not a report — produces a tier-0 report saying so. None of them can produce an
empty findings list that reads like a clean result.
"""

import contextlib
import fcntl
import json
import os
import subprocess
import sys
import tempfile
import time

from django.conf import settings

from apk_engine.report import unexaminable

TIMEOUT_SECONDS = int(os.environ.get('APK_ENGINE_TIMEOUT_SECONDS', '900'))
MEMORY_MB = int(os.environ.get('APK_ENGINE_MEMORY_MB', '6144'))
STDOUT_LIMIT_BYTES = 64 * 1024 * 1024

# One examination at a time on this machine, across every gunicorn worker.
# androguard needs roughly 0.1 GB per MB of DEX — a large commercial app peaks
# near 3 GB — and during development three concurrent analyses exhausted a 15 GB
# workstation until it froze. Officers queue behind each other instead; a queue
# that does not clear within LOCK_WAIT_SECONDS is reported, not waited out.
LOCK_PATH = os.environ.get('APK_ENGINE_LOCK',
                           os.path.join(tempfile.gettempdir(), 'netforensiq-apk-engine.lock'))
LOCK_WAIT_SECONDS = int(os.environ.get('APK_ENGINE_LOCK_WAIT_SECONDS', '600'))


class _Busy(Exception):
    pass


@contextlib.contextmanager
def _exclusive():
    handle = open(LOCK_PATH, 'a+')
    deadline = time.monotonic() + LOCK_WAIT_SECONDS
    try:
        while True:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise _Busy()
                time.sleep(0.5)
        yield
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(handle, fcntl.LOCK_UN)
        handle.close()


def _engine_python():
    # In the container this is a copy of the interpreter *without* the
    # CAP_NET_RAW file capability the web interpreter carries for live capture
    # (see Dockerfile) — the process parsing a hostile file has no business
    # holding raw-socket rights.
    return os.environ.get('APK_ENGINE_PYTHON') or sys.executable


def run_examination(apk_path, container_path=None, original_name=''):
    backend = str(settings.BASE_DIR)
    command = [
        _engine_python(), '-m', 'apk_engine', 'examine',
        '--apk', str(apk_path), '--name', original_name or '',
        '--max-memory-mb', str(MEMORY_MB),
        '--max-cpu-seconds', str(TIMEOUT_SECONDS + 60),
    ]
    if container_path:
        command += ['--container', str(container_path)]

    environment = {
        'PATH': os.environ.get('PATH', '/usr/local/bin:/usr/bin:/bin'),
        'PYTHONPATH': backend,
        'LANG': 'C.UTF-8',
        'PYTHONDONTWRITEBYTECODE': '1',
    }
    if os.environ.get('APK_ENGINE_BASELINES'):
        environment['APK_ENGINE_BASELINES'] = os.environ['APK_ENGINE_BASELINES']

    try:
        with _exclusive():
            completed = subprocess.run(
                command, cwd=backend, env=environment, capture_output=True,
                timeout=TIMEOUT_SECONDS, start_new_session=True, check=False)
    except _Busy:
        return unexaminable(
            f'Another examination was still running after {LOCK_WAIT_SECONDS} seconds. '
            'The sample is sealed; examine it again when the other one finishes.')
    except subprocess.TimeoutExpired:
        return unexaminable(
            f'The examination did not finish within {TIMEOUT_SECONDS} seconds and was stopped.')
    except OSError as exc:
        return unexaminable(f'The examination engine could not be started: {exc}')

    stdout = completed.stdout[:STDOUT_LIMIT_BYTES]
    try:
        report = json.loads(stdout)
        if not isinstance(report, dict) or 'assessment' not in report:
            raise ValueError('output is not an examination report')
        return report
    except ValueError as exc:
        tail = completed.stderr.decode('utf-8', 'replace').strip().splitlines()[-3:]
        reason = ('The examination engine stopped without producing a report '
                  f'(exit status {completed.returncode}')
        if completed.returncode < 0:
            reason += f', signal {-completed.returncode}'
        reason += ').'
        if 'MemoryError' in ' '.join(tail):
            reason += f' It exceeded its {MEMORY_MB} MB memory limit.'
        report = unexaminable(reason)
        report['errors'].append(f'{type(exc).__name__}: {exc}')
        report['errors'].extend(line[:300] for line in tail)
        return report
