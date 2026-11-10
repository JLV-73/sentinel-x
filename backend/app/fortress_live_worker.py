"""One gated worker; URL is passed on stdin, never in argv or logs."""
import json
import sys
import ctypes
import os
from .fortress_live import observe, _OUTPUT_LIMIT


def main():
    if sys.stdin.buffer.readline(4) != b'GO\n':
        return 1
    if os.name != 'nt':
        return 1
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
    kernel.CreateMutexW.restype = ctypes.c_void_p
    ctypes.set_last_error(0)
    # Held by the child until process exit, including if its parent crashes.
    # This closes the job-termination / parent-mutex-release race.
    mutex = kernel.CreateMutexW(None, True, 'Global\\SentinelXFortressWorkerV022')
    error = ctypes.get_last_error()
    if not mutex or error == 183:
        return 1
    raw = sys.stdin.buffer.read(8193)
    if len(raw) > 8192:
        return 1
    try:
        url = json.loads(raw)
        from .fortress_live import validate_url
        from .fortress_mvp_api import _valid_observation
        observed = observe(url)
        if not _valid_observation(observed, validate_url(url)[3]):
            return 1
        output = json.dumps(observed, separators=(',', ':')).encode('ascii')
    except Exception:
        return 1
    if len(output) > _OUTPUT_LIMIT:
        return 1
    sys.stdout.buffer.write(output)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
