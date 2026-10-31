import importlib.util
import http.client
import threading
from pathlib import Path

PATH = Path(__file__).resolve().parents[1] / 'scripts' / 'fortress_lab_demo.py'

def load_lab():
    spec = importlib.util.spec_from_file_location('lab_security', PATH)
    lab = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lab)
    return lab

def test_slow_drip_cannot_extend_lab_lifetime():
    import socket
    import subprocess
    import sys
    import time
    from urllib.parse import urlsplit
    process = subprocess.Popen([sys.executable, str(PATH)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    client = None
    try:
        url = urlsplit(process.stdout.readline().strip())
        started = time.monotonic()
        client = socket.create_connection((url.hostname, url.port), timeout=2)
        client.sendall(b'GET /lab/ HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Slow: ')
        disconnected = False
        while time.monotonic() - started < 63 and process.poll() is None:
            if not disconnected:
                try:
                    client.sendall(b'x')
                except OSError:
                    disconnected = True
            time.sleep(0.5)
        assert process.poll() == 0, 'slow client extended the 60-second lab lifetime'
        with socket.socket() as probe:
            probe.settimeout(1)
            assert probe.connect_ex((url.hostname, url.port)) != 0
    finally:
        if client is not None:
            client.close()
        if process.poll() is None:
            process.terminate()
        process.communicate(timeout=5)


def test_slow_request_is_cut_off_without_blocking_next_page():
    import socket
    import subprocess
    import sys
    import time
    from urllib.parse import urlsplit
    process = subprocess.Popen([sys.executable, str(PATH)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    client = None
    try:
        url = urlsplit(process.stdout.readline().strip())
        client = socket.create_connection((url.hostname, url.port), timeout=2)
        client.sendall(b'GET /lab/ HTTP/1.1\r\nX-Slow: ')
        start = time.monotonic()
        while time.monotonic() - start < 3:
            try:
                client.sendall(b'x')
            except OSError:
                pass
            time.sleep(.2)
        conn = http.client.HTTPConnection(url.hostname, url.port, timeout=3)
        try:
            conn.request('GET', '/lab/')
            response = conn.getresponse()
            assert response.status == 200
            response.read()
        finally:
            conn.close()
    finally:
        if client is not None:
            client.close()
        if process.poll() is None:
            process.terminate()
        process.communicate(timeout=5)


def test_windows_launcher_ctrl_break_stops_owned_processes():
    import ctypes
    from ctypes import wintypes
    import os
    import signal
    import socket
    import subprocess
    import sys
    from urllib.parse import urlsplit
    import pytest
    if sys.platform != 'win32':
        pytest.skip('Windows console control event')
    if os.environ.get('FORTRESS_LAB_ISOLATED_CONSOLE') != '1':
        # Console control events must never be sent on the caller's console.
        env = os.environ.copy()
        env['FORTRESS_LAB_ISOLATED_CONSOLE'] = '1'
        result = subprocess.run(
            [sys.executable, '-I', '-B', '-m', 'pytest', '--import-mode=importlib',
             '-p', 'no:cacheprovider', str(PATH.parents[1] / 'tests' / 'test_fortress_lab_demo.py')
             + '::test_windows_launcher_ctrl_break_stops_owned_processes', '-q'],
            env=env, capture_output=True, text=True, errors='replace',
            creationflags=subprocess.CREATE_NEW_CONSOLE, timeout=90)
        assert result.returncode == 0, result.stdout + result.stderr
        return
    class Entry(ctypes.Structure):
        _fields_ = [('size', wintypes.DWORD), ('usage', wintypes.DWORD), ('pid', wintypes.DWORD),
                    ('heap', ctypes.c_size_t), ('module', wintypes.DWORD), ('threads', wintypes.DWORD),
                    ('parent', wintypes.DWORD), ('priority', ctypes.c_long), ('flags', wintypes.DWORD),
                    ('exe', wintypes.WCHAR * 260)]
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(Entry)]
    kernel.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(Entry)]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    def descendants(root):
        snap = kernel.CreateToolhelp32Snapshot(2, 0)
        entry = Entry(); entry.size = ctypes.sizeof(entry)
        pairs = []
        try:
            ok = kernel.Process32FirstW(snap, ctypes.byref(entry))
            while ok:
                pairs.append((entry.pid, entry.parent))
                ok = kernel.Process32NextW(snap, ctypes.byref(entry))
        finally:
            kernel.CloseHandle(snap)
        if root is None:
            return {pid for pid, _ in pairs}
        found = {root}
        while True:
            new = found | {pid for pid, parent in pairs if parent in found}
            if new == found:
                return found - {root}
            found = new
    process = subprocess.Popen(['cmd.exe', '/c', str(PATH.parents[1] / 'START_FORTRESS_LAB.cmd')],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                               text=True, errors='replace', creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
    address = None
    try:
        while True:
            line = process.stdout.readline()
            assert line, 'launcher exited before URL'
            if line.startswith('http://127.0.0.1:'):
                url = urlsplit(line.strip()); address = (url.hostname, url.port); break
        children = descendants(process.pid)
        assert children
        conn = http.client.HTTPConnection(*address, timeout=3)
        conn.request('GET', '/lab/')
        response = conn.getresponse(); response.read(); conn.close()
        assert response.status == 200
        slow = socket.create_connection(address, timeout=2)
        slow.sendall(b'GET /lab/ HTTP/1.1\r\nX-Slow: ')
        try:
            process.send_signal(signal.CTRL_BREAK_EVENT)
            process.wait(timeout=8)
        finally:
            slow.close()
        assert process.returncode == 0, f'launcher exit code {process.returncode}'
        assert not (children & descendants(None)), 'launcher left owned children alive'
        with socket.socket() as probe:
            probe.settimeout(1)
            assert probe.connect_ex(address) != 0
    finally:
        if process.poll() is None:
            # Let only this owned lab expire naturally; no force-kill.
            process.wait(timeout=65)
        process.communicate(timeout=5)


def test_cross_site_get_never_executes(monkeypatch):
    lab = load_lab()
    calls = []
    monkeypatch.setattr(lab, 'run_demo', lambda: calls.append(True) or {})
    with lab.http.server.HTTPServer(('127.0.0.1', 0), lab._Handler) as server:
        thread = threading.Thread(target=server.handle_request)
        thread.start()
        conn = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=3)
        conn.request('GET', '/lab/observation', headers={'Sec-Fetch-Site': 'cross-site', 'Sec-Fetch-Mode': 'no-cors', 'Sec-Fetch-Dest': 'image'})
        response = conn.getresponse()
        response.read()
        conn.close()
        thread.join(3)
        assert not calls
        assert response.status != 200


def test_requests_fail_closed_and_valid_post(monkeypatch):
    import secrets
    import json
    lab = load_lab()
    calls = []
    monkeypatch.setattr(lab, 'run_demo', lambda: calls.append(True) or {'ok': True})
    with lab.http.server.HTTPServer(('127.0.0.1', 0), lab._Handler) as server:
        server.capability = secrets.token_urlsafe(32)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        host = '127.0.0.1:' + str(server.server_port)
        good = [('Host', host), ('Origin', 'http://' + host), ('Content-Length', '0'),
                ('Sec-Fetch-Site', 'same-origin'), ('Sec-Fetch-Mode', 'cors'),
                ('Sec-Fetch-Dest', 'empty'), ('X-Fortress-Capability', server.capability)]
        def req(method, path, headers):
            conn = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=3)
            conn.putrequest(method, path, skip_host=True)
            for k, v in headers: conn.putheader(k, v)
            conn.endheaders()
            r = conn.getresponse(); body = r.read(); headers = dict(r.getheaders()); status = r.status
            conn.close()
            return status, body, headers
        try:
            for site in ['cross-site', 'same-site']:
                assert req('GET', '/lab/', [('Host', host), ('Sec-Fetch-Site', site)])[0] == 403
            status, page, headers = req('GET', '/lab/', [('Host', host), ('Sec-Fetch-Site', 'none')])
            assert status == 200 and server.capability.encode() in page
            assert headers['Cross-Origin-Resource-Policy'] == 'same-origin'
            assert "frame-ancestors 'none'" in headers['Content-Security-Policy']
            assert 'Access-Control-Allow-Origin' not in headers
            bad = []
            for name in ['Host', 'Origin', 'Sec-Fetch-Site', 'Sec-Fetch-Mode', 'Sec-Fetch-Dest', 'X-Fortress-Capability']:
                bad.append([pair for pair in good if pair[0] != name])
                bad.append(good + [next(pair for pair in good if pair[0] == name)])
            bad += [[(k, ('cross-site' if k == 'Sec-Fetch-Site' else v)) for k,v in good],
                    [(k, ('http://evil.invalid' if k == 'Origin' else v)) for k,v in good],
                    [(k, ('wrong' if k == 'X-Fortress-Capability' else v)) for k,v in good],
                    good + [('Content-Type', 'text/plain')], good + [('Transfer-Encoding', 'chunked')],
                    good + [('Content-Length', '1')]]
            for headers in bad:
                assert req('POST', '/lab/observation', headers)[0] != 200
            for method, path in [('GET','/lab/observation'), ('POST','/lab/'), ('POST','/lab/observation?x=1'), ('OPTIONS','/lab/observation'), ('PUT','/lab/observation')]:
                status, body, headers = req(method, path, good)
                assert status != 200 and 'Access-Control-Allow-Origin' not in headers
            assert not calls
            status, body, headers = req('POST', '/lab/observation', good)
            assert status == 200 and json.loads(body) == {'ok': True} and len(calls) == 1
            assert server.capability.encode() not in body
        finally:
            server.shutdown(); thread.join(3)


def test_fixture_cleanup_and_no_dns(monkeypatch):
    import json
    import socket
    import pytest
    lab = load_lab()
    addresses = []
    connect = lab._LabSocket.connect
    def checked(self, destination):
        addresses.append(self._address)
        with socket.socket() as competitor:
            if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
                competitor.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            with pytest.raises(OSError): competitor.bind(self._address)
        return connect(self, destination)
    real_socket_connect = socket.socket.connect
    def loopback_only(sock, address):
        assert address[0] == '127.0.0.1' and address in addresses
        return real_socket_connect(sock, address)
    monkeypatch.setattr(socket.socket, 'connect', loopback_only)
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **k: pytest.fail('unexpected DNS'))
    monkeypatch.setattr(lab._LabSocket, 'connect', checked)
    result = lab.run_demo()
    assert result['observation']['cookies']['count'] == 2
    assert 'lab-cookie-value-sentinel' not in json.dumps(result)
    assert not [t for t in threading.enumerate() if t.name == 'fortress-lab-fixture']
    with socket.socket() as client:
        client.settimeout(.3); assert client.connect_ex(addresses[-1]) != 0
    def failed(self, destination):
        addresses.append(self._address)
        raise OSError('synthetic')
    monkeypatch.setattr(lab._LabSocket, 'connect', failed)
    with pytest.raises(RuntimeError): lab.run_demo()
    assert not [t for t in threading.enumerate() if t.name == 'fortress-lab-fixture']
    with socket.socket() as client:
        client.settimeout(.3); assert client.connect_ex(addresses[-1]) != 0


def test_first_connection_theft_only_causes_failure(monkeypatch):
    import socket
    import time
    import pytest
    lab = load_lab()
    address = []
    connect = lab._LabSocket.connect
    def steal(self, destination):
        address.append(self._address)
        with socket.socket() as intruder:
            intruder.settimeout(1)
            intruder.connect(self._address)
            intruder.sendall(b'not a fixture request\r\n\r\n')
        time.sleep(.2)
        with socket.socket() as substitute:
            if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
                substitute.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            with pytest.raises(OSError): substitute.bind(self._address)
        return connect(self, destination)
    monkeypatch.setattr(lab._LabSocket, 'connect', steal)
    with pytest.raises(RuntimeError): lab.run_demo()
    assert not [t for t in threading.enumerate() if t.name == 'fortress-lab-fixture']
    with socket.socket() as client:
        client.settimeout(.3); assert client.connect_ex(address[-1]) != 0
