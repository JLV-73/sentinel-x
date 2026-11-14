"""ASGI + supervised worker + owned TLS fixture; never an Internet observation."""
import json
import os
import socket
import ssl
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from app import fortress_discovery_worker as worker
from app.fortress_job import run_gated
from test_fortress_discovery_vertical import client_and_auth
import test_discovery_gated_fixture as fixture


@pytest.mark.skipif(os.name != 'nt', reason='Windows supervised job fixture')
@pytest.mark.parametrize('trusted,partial,chunked', [(True, False, False), (False, False, False), (True, True, False), (True, False, True)], ids=['success', 'untrusted-certificate', 'partial-body', 'chunked-gzip'])
def test_asgi_supervised_loopback_tls_diagnostic(monkeypatch, tmp_path, trusted, partial, chunked):
    certs = Path(worker.__file__).with_name('fortress_mvp_tls')
    cert, key = certs / 'server.pem', certs / 'server-key.pem'
    if not trusted:
        cert, key = tmp_path / 'untrusted.pem', tmp_path / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(key), '-out', str(cert), '-days', '1',
                        '-subj', '/CN=standard-lab.invalid'], check=True, capture_output=True)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    listener.settimeout(10)
    port = listener.getsockname()[1]
    calls, errors = [], []

    def serve():
        try:
            conn, _ = listener.accept()
            with conn:
                conn.settimeout(5)
                try:
                    tls = context.wrap_socket(conn, server_side=True)
                except (ssl.SSLError, ConnectionResetError) as exc:
                    if trusted:
                        errors.append(repr(exc))
                    return
                with tls:
                    data = b''
                    while b'\r\n\r\n' not in data:
                        part = tls.recv(4096)
                        if not part:
                            raise RuntimeError('truncated request')
                        data += part
                    calls.append(data)
                    body = b'<p>LOCAL_SECRET_BODY</p>'
                    if chunked:
                        import gzip
                        encoded = gzip.compress(body)
                        response = (b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n'
                                    + f'{len(encoded):x}'.encode() + b'\r\n' + encoded + b'\r\n0\r\n\r\n')
                    else:
                        response = (b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: '
                                    + str(len(body) + (5 if partial else 0)).encode() + b'\r\n\r\n' + body)
                    tls.sendall(response)
                    try:
                        tls.unwrap().close()
                    except (ssl.SSLError, OSError):
                        pass
        except Exception as exc:
            errors.append(repr(exc))

    thread = threading.Thread(target=serve)
    thread.start()
    backend = str(Path(worker.__file__).resolve().parents[1])
    gates = []
    def gate(argv, timeout, payload, **kwargs):
        gates.append(True)
        args = [sys.executable, '-I', '-B', str(Path(fixture.__file__).resolve()),
                'fixture-child', backend, 'live_tls', str(port), '']
        return run_gated(args, timeout, payload, **kwargs)
    monkeypatch.setattr(worker, 'run_gated', gate)
    client, auth = client_and_auth()
    try:
        response = client.post('/api/fortress/discovery/live', headers=auth, json={
            'authorized': True, 'target': f'https://standard-lab.invalid:{port}/', 'routes': ['/'],
            'limits': {'pages': 1, 'requests': 1, 'depth': 0, 'interval': 1,
                       'page_bytes': 4096, 'total_bytes': 4096, 'seconds': 10}})
    finally:
        thread.join(12)
        listener.close()
    assert not thread.is_alive() and not errors, errors
    assert gates == [True]
    assert response.status_code == 200, response.text
    result = response.json()
    assert result['provenance'] == 'live'  # The injected fixture makes this laboratory data.
    assert result['requests'] == 1
    assert result['diagnostic'] == ({'phase': 'parse' if partial else 'none', 'requests_sent': 1, 'responses_received': 1}
                                    if trusted else {'phase': 'tls', 'requests_sent': 0, 'responses_received': 0})
    assert result['complete'] is (trusted and not partial)
    assert len(result['pages']) == (1 if trusted else 0)
    if partial:
        assert result['pages'][0]['status'] == 200
        assert result['pages'][0]['state'] == 'incomplete'
        assert result['pages'][0]['observations'] is None and result['pages'][0]['findings'] == []
    assert len(calls) == (1 if trusted else 0)
    if trusted:
        assert calls[0].startswith(b'GET / HTTP/1.1\r\n')
    assert 'LOCAL_SECRET_BODY' not in response.text

    # Execute the actual frontend module via Vite on the exact ASGI JSON.
    frontend = Path(backend).parent / 'frontend'
    script = r'''const {createServer} = await import('vite');
const server = await createServer({server:{middlewareMode:true}, appType:'custom', logLevel:'silent'});
try {
 const parser = await server.ssrLoadModule('/src/discoveryApi.ts');
 let data=''; for await (const chunk of process.stdin) data += chunk;
 const x=JSON.parse(data); const y=parser.parseDiscoveryResponse(x,'live');
 if (JSON.stringify(x)!==JSON.stringify(y)) throw Error('parser changed response');
 console.log('frontend parser accepted unchanged');
} finally { await server.close(); }'''
    parsed = subprocess.run(['node', '--input-type=module', '-e', script], input=response.text, text=True,
                            cwd=str(frontend), capture_output=True, timeout=30)
    assert parsed.returncode == 0, parsed.stdout + parsed.stderr
    print(f"{('success' if trusted else 'tls failure')}: requests={result['requests']} diagnostic={result['diagnostic']}; {parsed.stdout.strip()}")
