import asyncio
import ctypes
import json
import os
import socket
import ssl
import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from app import fortress_live as live, fortress_mvp_api as api
from app.fortress_job import run_gated

CERTS = Path(__file__).resolve().parents[1] / 'app' / 'fortress_mvp_tls'


def test_special_relay_blocked_before_socket():
    for ip in ('192.88.99.1', '192.88.99.2'):
        rows = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, 443))]
        with patch('socket.getaddrinfo', return_value=rows), patch('socket.socket') as sock:
            assert live.observe('https://example.com/')['failure_code'] == 'blocked'
            sock.assert_not_called()


def test_child_does_not_inherit_keylog(tmp_path, monkeypatch):
    monkeypatch.setenv('SSLKEYLOGFILE', str(tmp_path / 'keys'))
    code = "import os,sys;sys.stdin.buffer.readline();print('SSLKEYLOGFILE' in os.environ)"
    assert run_gated([sys.executable, '-c', code], 5).strip() == b'False'


def test_tls_handshake_never_writes_inherited_keylog(tmp_path, monkeypatch):
    keyfile = tmp_path / 'keys'
    monkeypatch.setenv('SSLKEYLOGFILE', str(keyfile))
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(str(CERTS / 'server.pem'), str(CERTS / 'server-key.pem'))
    errors = []
    def serve():
        try:
            conn, _ = listener.accept()
            with server.wrap_socket(conn, server_side=True) as tls:
                tls.recv(4096)
                tls.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
        except Exception as e:
            errors.append(e)
    thread = threading.Thread(target=serve)
    thread.start()
    fake = MagicMock()
    fake.getpeername.return_value = ('8.8.8.8', 443)
    rows = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', 443))]
    real_socket = socket.socket
    def factory(*args, **kwargs):
        # observe's public socket is faked; loopback socket for real TLS is genuine
        return fake if threading.current_thread() is threading.main_thread() and not getattr(factory, 'loop', False) else real_socket(*args, **kwargs)
    try:
        original = live.exchange_connected
        def exchange_real(_sock, _host, _authority, path, context, deadline, out):
            context.load_verify_locations(cafile=str(CERTS / 'ca.pem'))
            factory.loop = True
            try:
                client = real_socket(socket.AF_INET, socket.SOCK_STREAM)
                client.settimeout(3)
                client.connect(listener.getsockname())
                with client:
                    original(client, 'standard-lab.invalid', 'standard-lab.invalid', path, context, deadline, out)
            finally:
                factory.loop = False
        with patch('socket.getaddrinfo', return_value=rows), patch('socket.socket', side_effect=factory), patch.object(live, 'exchange_connected', side_effect=exchange_real):
            out = live.observe('https://example.com/')
        assert out['http_status'] == 200
    finally:
        thread.join(5)
        listener.close()
    assert not thread.is_alive() and not errors
    assert not keyfile.exists()


def app_and_scope(path):
    app = FastAPI()
    api.install_disabled_route(app, ('http://127.0.0.1:5177',))
    headers = [(b'host', b'127.0.0.1:8007'), (b'origin', b'http://127.0.0.1:5177'),
               (b'x-sentinel-request', b'sync'), (b'x-sentinel-capability', api._CAPABILITY.encode()),
               (b'content-type', b'application/json')]
    return app, {'type': 'http', 'asgi': {'version': '3.0'}, 'http_version': '1.1', 'method': 'POST', 'scheme': 'http', 'path': path, 'raw_path': path.encode(), 'query_string': b'', 'headers': headers, 'server': ('127.0.0.1', 8007), 'client': ('127.0.0.1', 1)}


@pytest.mark.parametrize('path', ['/api/fortress/audit', '/api/fortress/mvp/demo'])
def test_body_overall_deadline_cancels_receive_and_no_work(path, monkeypatch):
    monkeypatch.setattr(api, '_BODY_TIMEOUT', .08, raising=False)
    app, scope = app_and_scope(path)
    messages, cancelled = [], []
    async def receive():
        try:
            await asyncio.sleep(.03)
            return {'type': 'http.request', 'body': b' ', 'more_body': True}
        except asyncio.CancelledError:
            cancelled.append(True)
            raise
    async def send(message):
        messages.append(message)
    async def run():
        await asyncio.wait_for(app(scope, receive, send), .5)
    with patch.object(api, '_run_live') as job, patch.object(api, 'run_demo') as demo:
        asyncio.run(run())
        job.assert_not_called()
        demo.assert_not_called()
    assert messages[0]['status'] == 408
    assert cancelled
    assert b'secret' not in b''.join(m.get('body', b'') for m in messages)


def test_nested_json_422_no_worker():
    from fastapi.testclient import TestClient
    app, _ = app_and_scope('/api/fortress/audit')
    headers = {'host':'127.0.0.1:8007', 'origin':'http://127.0.0.1:5177', 'x-sentinel-request':'sync', 'x-sentinel-capability':api._CAPABILITY, 'content-type':'application/json'}
    with patch.object(api, '_run_live') as job:
        response = TestClient(app).post('/api/fortress/audit', headers=headers, content=b'[' * 1200 + b']' * 1200)
        assert response.status_code == 422
        job.assert_not_called()


@pytest.mark.parametrize('already,release_ok,close_ok', [(False, False, True), (False, True, False), (False, False, False), (True, True, False)])
def test_mutex_cleanup_failure_never_succeeds(already, release_ok, close_ok):
    kernel = MagicMock()
    kernel.CreateMutexW.return_value = 123
    kernel.ReleaseMutex.return_value = release_ok
    kernel.CloseHandle.return_value = close_ok
    value = live.result('https://example.com/')
    with patch.object(ctypes, 'WinDLL', return_value=kernel), patch.object(ctypes, 'get_last_error', return_value=183 if already else 0), patch.object(api, 'run_gated', return_value=json.dumps(value).encode()):
        with pytest.raises(RuntimeError, match='Mutex cleanup failed'):
            api._run_live('https://example.com/', 'https://example.com/')
    kernel.CloseHandle.assert_called_once_with(123)
    if already:
        kernel.ReleaseMutex.assert_not_called()
    else:
        kernel.ReleaseMutex.assert_called_once_with(123)
    assert api._LIVE_LOCK.acquire(False)
    api._LIVE_LOCK.release()


def test_mutex_preserves_worker_error_when_cleanup_fails():
    kernel = MagicMock()
    kernel.CreateMutexW.return_value = 123
    kernel.ReleaseMutex.return_value = False
    kernel.CloseHandle.return_value = False
    with patch.object(ctypes, 'WinDLL', return_value=kernel), patch.object(ctypes, 'get_last_error', return_value=0), patch.object(api, 'run_gated', side_effect=ValueError('worker failed')):
        with pytest.raises(ValueError, match='worker failed') as exc:
            api._run_live('https://example.com/', 'https://example.com/')
    assert 'Mutex cleanup failed: release, close' in exc.value.__notes__
    kernel.CloseHandle.assert_called_once_with(123)
    assert api._LIVE_LOCK.acquire(False)
    api._LIVE_LOCK.release()


@pytest.mark.parametrize('path', ['/api/fortress/audit', '/api/fortress/mvp/demo'])
def test_disconnect_does_not_start_work(path):
    app, scope = app_and_scope(path)
    messages = []
    async def receive():
        return {'type': 'http.disconnect'}
    async def send(message):
        messages.append(message)
    with patch.object(api, '_run_live') as job, patch.object(api, 'run_demo') as demo:
        asyncio.run(app(scope, receive, send))
        job.assert_not_called()
        demo.assert_not_called()
    assert messages[0]['status'] == 400
