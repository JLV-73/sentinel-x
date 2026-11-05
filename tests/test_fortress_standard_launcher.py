"""Windows end-to-end probe of the dedicated synthetic standard launcher."""
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

import pytest

ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / 'START_FORTRESS_STANDARD_LAB.cmd'
OUT = ROOT / 'OUT' / 'standard-lab-launcher.json'


def worker(result_path, log_path):
    import ctypes
    from ctypes import wintypes

    class ProcessEntry(ctypes.Structure):
        _fields_ = [('dwSize', wintypes.DWORD), ('cntUsage', wintypes.DWORD),
                    ('th32ProcessID', wintypes.DWORD), ('th32DefaultHeapID', ctypes.c_size_t),
                    ('th32ModuleID', wintypes.DWORD), ('cntThreads', wintypes.DWORD),
                    ('th32ParentProcessID', wintypes.DWORD), ('pcPriClassBase', ctypes.c_long),
                    ('dwFlags', wintypes.DWORD), ('szExeFile', wintypes.WCHAR * 260)]

    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry)]
    kernel.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry)]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]

    def descendants(pid):
        snapshot = kernel.CreateToolhelp32Snapshot(2, 0)
        if snapshot == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        entries = []
        try:
            entry = ProcessEntry()
            entry.dwSize = ctypes.sizeof(entry)
            ok = kernel.Process32FirstW(snapshot, ctypes.byref(entry))
            while ok:
                entries.append((entry.th32ProcessID, entry.th32ParentProcessID, entry.szExeFile))
                ok = kernel.Process32NextW(snapshot, ctypes.byref(entry))
        finally:
            kernel.CloseHandle(snapshot)
        parents = {pid}
        found = []
        while True:
            children = [item for item in entries if item[1] in parents and item[0] not in parents]
            if not children:
                return found
            found.extend(children)
            parents.update(item[0] for item in children)

    def alive(handle):
        return kernel.WaitForSingleObject(handle, 0) == 258

    result = {'passed': False, 'network_scope': 'loopback GET /lab/ only; no audit or browser',
              'binding': 'ephemeral loopback port; no fixed-port conflict', 'owned_descendants': []}
    proc = None
    observed = []
    try:
        with open(log_path, 'wb') as log:
            proc = subprocess.Popen([os.environ.get('COMSPEC', 'cmd.exe'), '/d', '/c', str(LAUNCHER)],
                                    cwd=ROOT, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
            deadline = time.monotonic() + 25
            url = None
            while time.monotonic() < deadline:
                for pid, parent, name in descendants(proc.pid):
                    if not any(item['pid'] == pid for item in observed):
                        handle = kernel.OpenProcess(0x100000, False, pid)
                        if not handle:
                            raise ctypes.WinError(ctypes.get_last_error())
                        observed.append({'pid': pid, 'name': name, 'handle': handle})
                text = Path(log_path).read_text(encoding='utf-8', errors='replace')
                match = re.search(r'http://127\.0\.0\.1:(\d{1,5})/lab/', text)
                if match:
                    url = match.group(0)
                    port = int(match.group(1))
                    break
                if proc.poll() is not None:
                    raise RuntimeError('launcher exited before URL: ' + text)
                time.sleep(.1)
            if not url:
                raise RuntimeError('URL not printed within deadline')
            result['url'] = url
            result['owned_descendants'] = [{'pid': p['pid'], 'name': p['name']} for p in observed]
            if not observed:
                raise RuntimeError('no launcher descendants observed')
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(url, timeout=3) as response:
                result['http_status'] = response.status
                body = response.read().decode('utf-8')
            result['synthetic_marker'] = 'Synthetic lab only' in body and 'STANDARD LAB' in body
            if result['http_status'] != 200 or not result['synthetic_marker']:
                raise RuntimeError('unexpected lab response')
            proc.send_signal(signal.CTRL_BREAK_EVENT)
            result['ctrl_break_sent_to_owned_group'] = True
            proc.wait(timeout=12)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and any(alive(p['handle']) for p in observed):
                time.sleep(.1)
            result['launcher_exit_code'] = proc.returncode
            result['descendants_stopped'] = not any(alive(p['handle']) for p in observed)
            with socket.socket() as sock:
                sock.settimeout(1)
                result['port_closed'] = sock.connect_ex(('127.0.0.1', port)) != 0
            if not result['descendants_stopped'] or not result['port_closed']:
                raise RuntimeError('owned descendants or listener survived Ctrl+Break')
            result['passed'] = True
    except Exception as exc:
        result['error'] = '%s: %s' % (type(exc).__name__, exc)
    finally:
        if proc and proc.poll() is None:
            try:
                proc.send_signal(signal.CTRL_BREAK_EVENT)
                proc.wait(timeout=65)
            except Exception as exc:
                result['cleanup_error'] = repr(exc)
        for item in observed:
            kernel.CloseHandle(item['handle'])
        Path(result_path).write_text(json.dumps(result, indent=2), encoding='utf-8')
    return 0 if result['passed'] else 1


def test_exact_windows_launcher_http_and_ctrl_break():
    if os.name != 'nt':
        pytest.skip('Windows console control required')
    assert LAUNCHER.is_file(), 'dedicated standard launcher missing'
    scratch = os.environ['TMPDIR']
    with tempfile.TemporaryDirectory(prefix='standard-launcher-', dir=scratch) as tmp:
        result_path = Path(tmp) / 'result.json'
        log_path = Path(tmp) / 'launcher.log'
        console_path = Path(tmp) / 'console.log'
        with console_path.open('wb') as log:
            supervisor = subprocess.Popen([sys.executable, '-I', '-B', str(Path(__file__).resolve()),
                                           '--worker', str(result_path), str(log_path)],
                                          stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                          creationflags=subprocess.CREATE_NEW_CONSOLE | subprocess.CREATE_NEW_PROCESS_GROUP)
            try:
                code = supervisor.wait(timeout=110)
            except subprocess.TimeoutExpired:
                code = None
        result = json.loads(result_path.read_text(encoding='utf-8')) if result_path.exists() else {
            'passed': False, 'error': 'supervisor produced no result',
            'supervisor_log': console_path.read_text(encoding='utf-8', errors='replace')}
        result['supervisor_exit_code'] = code
        OUT.parent.mkdir(exist_ok=True)
        OUT.write_text(json.dumps(result, indent=2), encoding='utf-8')
        assert code == 0 and result['passed'], result


if __name__ == '__main__' and len(sys.argv) == 4 and sys.argv[1] == '--worker':
    sys.exit(worker(sys.argv[2], sys.argv[3]))
