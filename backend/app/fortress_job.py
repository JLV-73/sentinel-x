"""Experimental Windows job supervisor. Not connected to the audit route.

The child must read exactly GO\n on stdin before performing any operation.
This module does not by itself qualify the child, network policy or exclusion.
"""
import ctypes
from ctypes import wintypes
import os
import subprocess
import time


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


def run_gated(args, timeout, payload=b''):
    """Run a trusted gated child in a kill-on-close job, or fail closed.

    Timeout starts before process creation. No child output is returned unless
    it exits successfully and the job closes successfully. This experimental
    helper is not a concurrent-request lock and is not wired to a route.
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
    job = kernel.CreateJobObjectW(None, None)
    if not job:
        raise ctypes.WinError(ctypes.get_last_error())
    child = None
    try:
        limits = _ExtendedLimits()
        limits.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not kernel.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            raise ctypes.WinError(ctypes.get_last_error())
        child_env = os.environ.copy()
        child_env.pop('SSLKEYLOGFILE', None)
        child = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, close_fds=True,
                                 creationflags=subprocess.CREATE_NO_WINDOW, env=child_env)
        if not kernel.AssignProcessToJobObject(job, int(child._handle)):
            raise ctypes.WinError(ctypes.get_last_error())
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('job deadline')
        try:
            output, _ = child.communicate(input=b'GO\n' + payload, timeout=remaining)
        except subprocess.TimeoutExpired:
            raise TimeoutError('job deadline') from None
        if child.returncode != 0:
            raise RuntimeError('child failed')
        return output
    finally:
        if child is not None and child.stdin and not child.stdin.closed:
            child.stdin.close()
        closed = kernel.CloseHandle(job)
        if child is not None and child.poll() is None:
            # Covers assignment failure too; no network may begin before gate.
            child.kill()
            child.wait(timeout=5)
        if not closed:
            raise ctypes.WinError(ctypes.get_last_error())
