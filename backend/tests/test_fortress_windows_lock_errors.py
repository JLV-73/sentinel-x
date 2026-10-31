"""Fault injection tests; these are not native ACL or cross-session proofs."""
import ctypes
import os

import pytest
from app import fortress_service as service

pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Windows ctypes last-error API')


@pytest.mark.parametrize('failure', ['create', 'existing', 'wait_timeout', 'wait_failed', 'wait_exception'])
def test_mutex_errors_refuse_and_close_open_handle(monkeypatch, failure):
    class Kernel:
        closed = []
        def CreateMutexW(self, *args):
            if failure == 'create':
                ctypes.set_last_error(5)
                return None
            ctypes.set_last_error(183 if failure == 'existing' else 0)
            return 123
        def WaitForSingleObject(self, *args):
            if failure == 'wait_exception':
                raise OSError('sensitive diagnostic')
            return {'wait_timeout': 258, 'wait_failed': 0xffffffff}.get(failure, 0)
        def CloseHandle(self, handle):
            self.closed.append(handle)
            return 1
    kernel = Kernel()
    monkeypatch.setattr(service, '_mutex_api', lambda: kernel)
    with pytest.raises(service.AuditError, match='^audit unavailable$'):
        service._acquire_process_mutex()
    assert kernel.closed == ([] if failure == 'create' else [123])


@pytest.mark.parametrize('failure', ['release_false', 'release_exception', 'close_false', 'close_exception'])
def test_release_failure_is_reported_and_close_attempted(monkeypatch, failure):
    class Kernel:
        closed = []
        def CreateMutexW(self, *args):
            ctypes.set_last_error(0)
            return 123
        def WaitForSingleObject(self, *args):
            return 0
        def ReleaseMutex(self, handle):
            if failure == 'release_exception':
                raise OSError('private')
            return failure != 'release_false'
        def CloseHandle(self, handle):
            self.closed.append(handle)
            if failure == 'close_exception':
                raise OSError('private')
            return failure != 'close_false'
    kernel = Kernel()
    monkeypatch.setattr(service, '_mutex_api', lambda: kernel)
    handle = service._acquire_process_mutex()
    with pytest.raises(service.AuditError, match='mutex cleanup'):
        service._release_process_mutex(handle)
    assert kernel.closed == [123]


def test_release_uses_api_captured_when_acquired(monkeypatch):
    class Kernel:
        closed = []
        def CreateMutexW(self, *args):
            ctypes.set_last_error(0)
            return 123
        def WaitForSingleObject(self, *args): return 0
        def ReleaseMutex(self, handle): return 1
        def CloseHandle(self, handle):
            self.closed.append(handle)
            return 1
    kernel = Kernel()
    monkeypatch.setattr(service, '_mutex_api', lambda: kernel)
    handle = service._acquire_process_mutex()
    def broken_api():
        raise OSError('WinDLL unavailable')
    monkeypatch.setattr(service, '_mutex_api', broken_api)
    service._release_process_mutex(handle)
    assert kernel.closed == [123]


def test_audit_exception_is_preserved_if_cleanup_fails(monkeypatch):
    marker = RuntimeError('sentinel')
    monkeypatch.setattr(service, '_validate', lambda *args: (object(), ('route',), 'standard'))
    monkeypatch.setattr(service, '_acquire_process_mutex', lambda: object())
    def bad_release(_):
        raise service.AuditError('mutex cleanup failed')
    monkeypatch.setattr(service, '_release_process_mutex', bad_release)
    monkeypatch.setattr(service, 'evaluate_findings', lambda *args, **kwargs: (_ for _ in ()).throw(marker))
    with pytest.raises(RuntimeError) as caught:
        service._audit_with_factory({}, factory=lambda *args, **kwargs: None)
    assert caught.value is marker
    assert any('mutex cleanup' in note for note in caught.value.__notes__)
    assert service._AUDIT_LOCK.acquire(blocking=False)
    service._AUDIT_LOCK.release()


def test_acquire_close_failure_preserves_refusal_and_reports_risk(monkeypatch):
    class Kernel:
        def CreateMutexW(self, *args):
            ctypes.set_last_error(183)
            return 123
        def CloseHandle(self, handle): return 0
    monkeypatch.setattr(service, '_mutex_api', lambda: Kernel())
    with pytest.raises(service.AuditError, match='audit unavailable') as caught:
        service._acquire_process_mutex()
    assert any('handle may remain open' in note for note in caught.value.__notes__)


def test_api_load_failure_is_redacted(monkeypatch):
    def broken(): raise OSError('private')
    monkeypatch.setattr(service, '_mutex_api', broken)
    with pytest.raises(service.AuditError, match='^audit unavailable$'):
        service._acquire_process_mutex()


def test_cleanup_failure_prevents_audit_result(monkeypatch):
    monkeypatch.setattr(service, '_validate', lambda *args: (object(), ('route',), 'standard'))
    monkeypatch.setattr(service, '_acquire_process_mutex', lambda: object())
    monkeypatch.setattr(service, 'evaluate_findings', lambda *args, **kwargs: [])
    def bad_release(_): raise service.AuditError('mutex cleanup failed')
    monkeypatch.setattr(service, '_release_process_mutex', bad_release)
    with pytest.raises(service.AuditError, match='mutex cleanup'):
        service._audit_with_factory({}, factory=lambda *args, **kwargs: None)
    assert service._AUDIT_LOCK.acquire(blocking=False)
    service._AUDIT_LOCK.release()
