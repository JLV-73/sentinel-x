import importlib.util
from pathlib import Path


def test_live_owned_fixture_observation():
    path = Path(__file__).resolve().parents[2] / 'scripts' / 'fortress_lab_demo.py'
    assert path.is_file(), 'separate lab entrypoint must exist'
    spec = importlib.util.spec_from_file_location('fortress_lab_demo', path)
    lab = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lab)
    result = lab.run_demo()
    assert result['observation']['outcome'] == 'ok'
    assert result['observation']['cookies']['count'] == 2
    assert result['observation']['cookies']['missing_secure'] == 1
    assert result['fixture']['requests'] == 1
    assert result['fixture']['actual_peer_loopback'] is True


import json
import re
import socket
import subprocess
import sys
import threading
from urllib.parse import urlsplit
from http.client import HTTPConnection
import pytest

PATH = Path(__file__).resolve().parents[2] / 'scripts' / 'fortress_lab_demo.py'


def load_lab():
    spec = importlib.util.spec_from_file_location('fortress_lab_demo', PATH)
    lab = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lab)
    return lab


def closed(address):
    with socket.socket() as sock:
        sock.settimeout(.5)
        return sock.connect_ex(address) != 0


def test_two_runs_and_error_close_fixture(monkeypatch, capsys):
    lab = load_lab()
    addresses, workers, listeners = [], [], []
    fixture_ready = threading.Event()
    real_connect, real_fixture = lab._LabSocket.connect, lab._fixture
    def tracked_fixture(listener, stop, evidence, deadline):
        workers.append(threading.current_thread())
        listeners.append(listener)
        fixture_ready.set()
        return real_fixture(listener, stop, evidence, deadline)
    def tracked_connect(self, destination):
        addresses.append(self._address)
        assert self._address[0] == '127.0.0.1'
        assert fixture_ready.wait(2)
        assert self._listener is listeners[-1]
        with socket.socket() as competitor:
            if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
                competitor.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            with pytest.raises(OSError):
                competitor.bind(self._address)
        real_connect(self, destination)
        assert self._socket.getpeername() == self._address
    monkeypatch.setattr(lab, '_fixture', tracked_fixture)
    monkeypatch.setattr(lab._LabSocket, 'connect', tracked_connect)
    sentinels = ('lab-cookie-name-sentinel', 'lab-cookie-value-sentinel', 'lab-body-sentinel')
    for _ in range(2):
        fixture_ready.clear()
        result = lab.run_demo()
        assert result['observation'] == {'outcome': 'ok', 'cookies': {'count': 2, 'missing_secure': 1, 'missing_httponly': 1, 'missing_samesite': 1, 'indeterminate': 0}}
        assert result['fixture'] == {'requests': 1, 'actual_peer_loopback': True}
        assert closed(addresses[-1]) and not workers[-1].is_alive() and listeners[-1].fileno() == -1
        assert all(s not in json.dumps(result) for s in sentinels)
    assert all(s not in str(capsys.readouterr()) for s in sentinels)
    def fail_connect(self, destination):
        addresses.append(self._address)
        raise OSError('synthetic failure')
    monkeypatch.setattr(lab._LabSocket, 'connect', fail_connect)
    with pytest.raises(RuntimeError):
        lab.run_demo()
    assert closed(addresses[-1]) and not workers[-1].is_alive() and listeners[-1].fileno() == -1
    assert len(workers) == len(listeners) == len(addresses) == 3
    assert all(s not in str(capsys.readouterr()) for s in sentinels)


def test_adapter_rejects_other_destinations():
    lab = load_lab()
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        adapter = lab._LabSocket(listener)
        try:
            with pytest.raises(RuntimeError):
                adapter.connect(('8.8.8.8', 80))
            with pytest.raises(RuntimeError):
                adapter.connect((lab.FAKE_IP, 443))
        finally:
            adapter.close()


def test_cli_rejects_target_host_and_port():
    for arg in ('https://example.invalid/', '--host=127.0.0.1', '--port=80'):
        p = subprocess.run([sys.executable, str(PATH), arg], capture_output=True, text=True, timeout=5)
        assert p.returncode != 0 and 'No arguments accepted' in p.stderr


def test_separate_http_server_rejects_input_and_stops():
    p = subprocess.Popen([sys.executable, str(PATH)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    address = None
    try:
        parsed = urlsplit(p.stdout.readline().strip())
        assert parsed.hostname == '127.0.0.1' and parsed.path == '/lab/'
        address = (parsed.hostname, parsed.port)
        def get(path, headers=None):
            conn = HTTPConnection(*address, timeout=8)
            try:
                conn.request('GET', path, headers=headers or {})
                response = conn.getresponse()
                return response.status, response.read()
            finally:
                conn.close()
        status, page = get(parsed.path)
        assert status == 200
        match = re.search(rb"const capability='([A-Za-z0-9_-]+)'", page)
        assert match
        token = match.group(1).decode('ascii')
        headers = {'Origin': f'http://127.0.0.1:{parsed.port}', 'Content-Length': '0',
                   'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'cors',
                   'Sec-Fetch-Dest': 'empty', 'X-Fortress-Capability': token}
        def post(path, extra=None):
            conn = HTTPConnection(*address, timeout=8)
            try:
                conn.request('POST', path, headers={**headers, **(extra or {})})
                response = conn.getresponse()
                return response.status, response.read()
            finally:
                conn.close()
        endpoint = '/lab/observation'
        assert get(endpoint)[0] == 403
        assert post(endpoint + '?target=http://example.invalid')[0] == 403
        assert post(endpoint, {'Origin': 'http://evil.invalid'})[0] == 403
        assert post(endpoint, {'Host': 'evil.invalid'})[0] == 403
        assert post(endpoint, {'X-Fortress-Capability': 'invalid'})[0] == 403
        for _ in range(2):
            status, body = post(endpoint)
            assert status == 200
            result = json.loads(body)
            assert result['observation']['cookies']['count'] == 2
            assert all(s not in body for s in (b'lab-cookie-name-sentinel', b'lab-cookie-value-sentinel', b'lab-body-sentinel', token.encode()))
    finally:
        p.terminate()
        out, err = p.communicate(timeout=5)
    assert p.poll() is not None and address and closed(address)
    assert all(s not in out + err for s in ('lab-cookie-name-sentinel', 'lab-cookie-value-sentinel', 'lab-body-sentinel'))


def test_lab_page_served_with_restrictive_csp():
    p = subprocess.Popen([sys.executable, str(PATH)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    address = None
    try:
        parsed = urlsplit(p.stdout.readline().strip())
        address = (parsed.hostname, parsed.port)
        conn = HTTPConnection(parsed.hostname, parsed.port, timeout=5)
        conn.request('GET', '/lab/')
        response = conn.getresponse()
        body = response.read().decode('utf-8')
        assert response.status == 200
        assert "default-src 'none'" in response.getheader('Content-Security-Policy')
        assert "frame-ancestors 'none'" in response.getheader('Content-Security-Policy')
        assert 'NIGHTFALL' in body and '/lab/observation' in body
        assert "connect-src 'self'" in response.getheader('Content-Security-Policy')
        conn.close()
        for path, headers in [('/lab/?target=x', {}), ('/lab/', {'Host':'evil.invalid'}), ('/lab/', {'Origin':'http://evil.invalid'})]:
            conn = HTTPConnection(parsed.hostname, parsed.port, timeout=5)
            conn.request('GET', path, headers=headers)
            r = conn.getresponse()
            assert r.status == 403
            r.read()
            conn.close()
    finally:
        p.terminate()
        p.communicate(timeout=5)
    assert p.poll() is not None and address and closed(address)


def test_production_api_remains_unavailable():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from app.fortress_api import install_fortress_route
    app = FastAPI()
    install_fortress_route(app, ['http://127.0.0.1:5173'])
    with TestClient(app) as client:
        response = client.post('/api/fortress/audit', headers={'Origin': 'http://127.0.0.1:5173', 'X-Sentinel-Request': 'sync'}, json={})
    assert response.status_code == 503
