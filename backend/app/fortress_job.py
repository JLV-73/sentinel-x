"""Windows kill-on-close job supervisor for gated workers.

The child must read exactly GO\n on stdin before performing any operation.
This module does not by itself qualify the child, network policy or exclusion.
"""
import ctypes
from ctypes import wintypes
import os
import subprocess
import threading
import time

from .fortress_live import _OUTPUT_LIMIT


class _BasicLimits(ctypes.Structure):
    _fields_ = [('PerProcessUserTimeLimit', ctypes.c_longlong),
                ('PerJobUserTimeLimit', ctypes.c_longlong),
                ('LimitFlags', wintypes.DWORD),
                ('MinimumWorkingSetSize', ctypes.c_size_t),
                ('MaximumWorkingSetSize', ctypes.c_size_t),
                ('ActiveProcessLimit', wintypes.DWORD),
                ('Affinity', ctypes.c_size_t),
                ('PriorityClass', wintypes.DWORD),
                ('SchedulingClass', wintypes.DWORD)]


class _IoCounters(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in
                ('ReadOperationCount', 'WriteOperationCount', 'OtherOperationCount',
                 'ReadTransferCount', 'WriteTransferCount', 'OtherTransferCount')]


class _ExtendedLimits(ctypes.Structure):
    _fields_ = [('BasicLimitInformation', _BasicLimits), ('IoInfo', _IoCounters),
                ('ProcessMemoryLimit', ctypes.c_size_t), ('JobMemoryLimit', ctypes.c_size_t),
                ('PeakProcessMemoryUsed', ctypes.c_size_t), ('PeakJobMemoryUsed', ctypes.c_size_t)]


class _Accounting(ctypes.Structure):
    _fields_ = [('TotalUserTime', ctypes.c_longlong), ('TotalKernelTime', ctypes.c_longlong),
                ('ThisPeriodTotalUserTime', ctypes.c_longlong), ('ThisPeriodTotalKernelTime', ctypes.c_longlong),
                ('TotalPageFaultCount', wintypes.DWORD), ('TotalProcesses', wintypes.DWORD),
                ('ActiveProcesses', wintypes.DWORD), ('TotalTerminatedProcesses', wintypes.DWORD)]


def run_gated(args, timeout, payload=b''):
    """Run a trusted gated child in a kill-on-close job, or fail closed.

    Timeout starts before process creation. Stdout is bounded while read;
    stderr is discarded. Output is returned only after successful child exit
    and job cleanup. This helper does not provide concurrent-request locking.
    """
    if os.name != 'nt' or timeout <= 0:
        raise RuntimeError('Windows job unavailable')
    deadline = time.monotonic() + timeout
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel.SetInformationJobObject.restype = wintypes.BOOL
    kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel.TerminateJobObject.restype = wintypes.BOOL
    kernel.QueryInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p]
    kernel.QueryInformationJobObject.restype = wintypes.BOOL
    job = kernel.CreateJobObjectW(None, None)
    if not job:
        raise ctypes.WinError(ctypes.get_last_error())
    child = None
    assigned = False
    threads = []
    output = bytearray()
    result = b''
    completed = False
    try:
        limits = _ExtendedLimits()
        limits.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not kernel.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            raise ctypes.WinError(ctypes.get_last_error())
        child_env = os.environ.copy()
        child_env.pop('SSLKEYLOGFILE', None)
        child = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, close_fds=True, bufsize=0,
                                 creationflags=subprocess.CREATE_NO_WINDOW, env=child_env)
        if not kernel.AssignProcessToJobObject(job, int(child._handle)):
            raise ctypes.WinError(ctypes.get_last_error())
        assigned = True
        if time.monotonic() >= deadline:
            raise TimeoutError('job deadline')
        finished = threading.Event()
        state = {'overflow': False, 'read_error': False, 'write_error': False}

        def read_output():
            try:
                while True:
                    chunk = child.stdout.read(min(4096, _OUTPUT_LIMIT + 1 - len(output)))
                    if not chunk:
                        break
                    if len(output) + len(chunk) > _OUTPUT_LIMIT:
                        state['overflow'] = True
                        break
                    output.extend(chunk)
            except Exception:
                state['read_error'] = True
            finally:
                finished.set()

        def write_input():
            try:
                data = memoryview(b'GO\n' + payload)
                while data:
                    written = child.stdin.write(data)
                    if not written:
                        raise OSError('pipe write failed')
                    data = data[written:]
                child.stdin.close()
            except Exception:
                state['write_error'] = True

        for target in (read_output, write_input):
            thread = threading.Thread(target=target, daemon=True)
            thread.start()
            threads.append(thread)
        if not finished.wait(max(0, deadline - time.monotonic())):
            raise TimeoutError('job deadline')
        if state['overflow']:
            raise ValueError('Invalid result')
        if state['read_error']:
            raise RuntimeError('child pipe failed')
        try:
            child.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            raise TimeoutError('job deadline') from None
        if time.monotonic() >= deadline:
            raise TimeoutError('job deadline')
        threads[1].join(max(0, deadline - time.monotonic()))
        if threads[1].is_alive() or state['write_error'] or child.returncode != 0:
            raise RuntimeError('child failed')
        result = bytes(output)
        completed = True
    finally:
        cleanup_failed = False
        if assigned:
            if not kernel.TerminateJobObject(job, 1):
                cleanup_failed = True
            end = time.monotonic() + 5
            while True:
                accounting = _Accounting()
                if not kernel.QueryInformationJobObject(job, 1, ctypes.byref(accounting), ctypes.sizeof(accounting), None):
                    cleanup_failed = True
                    break
                if accounting.ActiveProcesses == 0:
                    break
                if time.monotonic() >= end:
                    cleanup_failed = True
                    break
                time.sleep(.01)
        elif child is not None and child.poll() is None:
            try:
                child.kill()
            except OSError:
                cleanup_failed = True
        if child is not None:
            try:
                child.wait(timeout=5)
            except Exception:
                cleanup_failed = True
        if not kernel.CloseHandle(job):
            cleanup_failed = True
        for thread in threads:
            thread.join(timeout=5)
            if thread.is_alive():
                cleanup_failed = True
        if child is not None:
            for pipe in (child.stdin, child.stdout):
                if pipe and not pipe.closed and not any(thread.is_alive() for thread in threads):
                    try:
                        pipe.close()
                    except OSError:
                        cleanup_failed = True
        output.clear()
        payload = b''
        if cleanup_failed:
            result = b''
            raise RuntimeError('job cleanup failed') from None
    if completed and time.monotonic() >= deadline:
        result = b''
        raise TimeoutError('job deadline')
    return result
