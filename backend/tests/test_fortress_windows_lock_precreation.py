"""Windows-only regression: a pre-existing object is not trusted as our mutex.

Tests use this user/session only and do not establish ACL or cross-session safety.
"""
import ctypes
import os
import queue
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from app.fortress_service import AuditError, _acquire_process_mutex, _mutex_api, _release_process_mutex

pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Windows mutex only')
NAME = r'Global\SentinelX-P2-DigitalFortress-Audit'
BACKEND = str(Path(__file__).resolve().parents[1])


def test_precreated_unowned_mutex_is_rejected():
    kernel = _mutex_api()
    handle = kernel.CreateMutexW(None, False, NAME)
    assert handle and ctypes.get_last_error() != 183, 'test requires an initially absent object'
    try:
        acquired = None
        try:
            with pytest.raises(AuditError, match='audit unavailable'):
                acquired = _acquire_process_mutex()
        finally:
            if acquired is not None:
                _release_process_mutex(acquired)
    finally:
        assert kernel.CloseHandle(handle)


def test_precreated_mutex_from_child_is_rejected_then_recovers():
    script = '''import ctypes, sys
sys.path.insert(0, sys.argv[1])
from app.fortress_service import _mutex_api
k = _mutex_api()
h = k.CreateMutexW(None, False, r'Global\\SentinelX-P2-DigitalFortress-Audit')
if not h or ctypes.get_last_error() == 183:
 print('unavailable', flush=True); sys.exit(1)
print('ready', flush=True)
sys.stdin.readline()
assert k.CloseHandle(h)
'''
    child = subprocess.Popen([sys.executable, '-I', '-B', '-c', script, BACKEND],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    ready = queue.Queue()
    reader = threading.Thread(target=lambda: ready.put(child.stdout.readline().strip()), daemon=True)
    reader.start()
    try:
        assert ready.get(timeout=10) == 'ready'
        acquired = None
        try:
            with pytest.raises(AuditError, match='audit unavailable'):
                acquired = _acquire_process_mutex()
        finally:
            if acquired is not None:
                _release_process_mutex(acquired)
    finally:
        try:
            child.communicate(input='close\n', timeout=10)
        except subprocess.TimeoutExpired:
            child.kill()  # Only this test's dedicated child.
            child.communicate(timeout=10)
            raise
        reader.join(timeout=2)
    assert child.returncode == 0
    handle = _acquire_process_mutex()
    _release_process_mutex(handle)
