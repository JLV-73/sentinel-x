import json
import os
import socket
import ssl
import sys
import threading
from pathlib import Path

import pytest
from app import fortress_discovery_worker as worker
from app.fortress_job import run_gated
from test_fortress_discovery_vertical import client_and_auth
import test_discovery_gated_fixture as fixture


@pytest.mark.skipif(os.name != 'nt', reason='Windows job fixture')
def test_resource_inventory_through_supervised_tls_and_api(monkeypatch):
    certs = Path(worker.__file__).with_name('fortress_mvp_tls')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(certs / 'server.pem'), str(certs / 'server-key.pem'))
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(4)
    listener.settimeout(2)
    port = listener.getsockname()[1]
    calls, errors = [], []
    body = (b'<script src="https://outside.invalid/secret?token=SECRETRESOURCE"></script>'
            b'<link rel="STYLESHEET" href="/secret.css"><script>SECRETCONTENT</script>')
    def serve():
        try:
            while True:
                try:
                    conn, _ = listener.accept()
                except socket.timeout:
                    return
                with conn, context.wrap_socket(conn, server_side=True) as tls:
                    request = b''
                    while b'\r\n\r\n' not in request:
                        request += tls.recv(4096)
                    calls.append(request.split(b' ')[1])
                    tls.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: '
                                + str(len(body)).encode() + b'\r\n\r\n' + body)
                    try:
                        tls.unwrap().close()
                    except (ssl.SSLError, OSError):
                        pass
        except Exception as exc:
            errors.append(repr(exc))
    thread = threading.Thread(target=serve)
    thread.start()
    backend = str(Path(worker.__file__).resolve().parents[1])
    def gate(argv, timeout, payload, **kwargs):
        return run_gated([sys.executable, '-I', '-B', str(Path(fixture.__file__).resolve()),
                          'fixture-child', backend, 'live_tls', str(port), ''], timeout, payload, **kwargs)
    monkeypatch.setattr(worker, 'run_gated', gate)
    client, auth = client_and_auth()
    limits = {'pages': 3, 'requests': 4, 'depth': 1, 'interval': 1,
              'page_bytes': 4096, 'total_bytes': 8192, 'seconds': 10}
    try:
        response = client.post('/api/fortress/discovery/live', headers=auth, json={
            'authorized': True, 'target': f'https://standard-lab.invalid:{port}/',
            'routes': ['/'], 'limits': limits})
    finally:
        thread.join(5)
        listener.close()
    assert not thread.is_alive() and not errors
    assert response.status_code == 200, response.text
    assert calls == [b'/']
    tls = response.json()['pages'][0]['tls']
    assert set(tls) == {'version', 'certificate_verified', 'hostname_verified', 'not_after'}
    assert tls['version'] in ('TLSv1.2', 'TLSv1.3')
    assert tls['certificate_verified'] is tls['hostname_verified'] is True
    assert tls['not_after'] is None or tls['not_after'].endswith('Z')
    assert response.json()['resources'] == [
        {'page': 'page-1', 'kind': 'script', 'count': 1},
        {'page': 'page-1', 'kind': 'stylesheet', 'count': 1}]
    assert all(value not in response.text for value in ('SECRETRESOURCE', 'SECRETCONTENT', 'outside.invalid', 'secret.css'))
