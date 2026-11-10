"""Cleanup failure must not turn a rejected worker result into success or retain it."""
import traceback
from unittest.mock import patch

import pytest
from app import fortress_mvp_api as api


class Call:
    def __init__(self, result):
        self.result = result
        self.calls = 0

    def __call__(self, *args):
        self.calls += 1
        return self.result


@pytest.mark.parametrize('failure', ['release', 'close'])
def test_cleanup_failure_keeps_rejection_sanitized(failure):
    class Kernel:
        CreateMutexW = Call(123)
        ReleaseMutex = Call(failure != 'release')
        CloseHandle = Call(failure != 'close')

    kernel = Kernel()
    with patch.object(api.ctypes, 'WinDLL', return_value=kernel), \
         patch.object(api.ctypes, 'get_last_error', return_value=0), \
         patch.object(api, 'run_gated', return_value=b'{"x":"FAKE_CLEANUP_MARKER",'):
        with pytest.raises(ValueError, match='Invalid result') as caught:
            api._run_live('https://example.invalid/', 'https://example.invalid/')
    exc = caught.value
    assert exc.__cause__ is None and exc.__context__ is None
    assert any('Mutex cleanup failed: ' + failure in n for n in exc.__notes__)
    assert kernel.ReleaseMutex.calls == 1 and kernel.CloseHandle.calls == 1
    captured = traceback.TracebackException.from_exception(exc, capture_locals=True)
    for frame in captured.stack:
        if frame.filename.replace('\\', '/').endswith('/app/fortress_mvp_api.py'):
            assert 'FAKE_CLEANUP_MARKER' not in repr(frame.locals)
    tb = exc.__traceback__
    while tb:
        if tb.tb_frame.f_code.co_filename.replace('\\', '/').endswith('/app/fortress_mvp_api.py'):
            assert 'FAKE_CLEANUP_MARKER' not in repr(tb.tb_frame.f_locals)
        tb = tb.tb_next
    assert api._LIVE_LOCK.acquire(blocking=False)
    api._LIVE_LOCK.release()
