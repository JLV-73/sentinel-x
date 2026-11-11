"""Cycle B acceptance: owned HTTPS loopback, no public network access."""
import json
import socket
import ssl
import threading
import time
from pathlib import Path

from app.fortress_live import exchange_connected, result

CERTS = Path(__file__).resolve().parents[1] / 'app' / 'fortress_mvp_tls'


def test_verified_head_is_analyzed_without_exposing_sensitive_values():
    response = (b'HTTP/1.1 200 OK\r\n'
                b'Strict-Transport-Security: max-age=0\r\n'
                b'Content-Security-Policy: script-src \'nonce-FAKE_NONCE_MARKER\'\r\n'
                b'Set-Cookie: FAKE_NAME=FAKE_COOKIE_MARKER; Secure; HttpOnly\r\n\r\n')
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    listener.settimeout(5)
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(str(CERTS / 'server.pem'), str(CERTS / 'server-key.pem'))
    requests, errors = [], []

    def serve():
        try:
            with listener.accept()[0] as connection:
                with server.wrap_socket(connection, server_side=True) as tls:
                    requests.append(tls.recv(4096))
                    tls.sendall(response)
        except Exception as exc:
            errors.append(type(exc).__name__)

    thread = threading.Thread(target=serve)
    thread.start()
    out = result('https://standard-lab.invalid/')
    out['mode'] = 'synthetic_loopback'  # lab harness only; not accepted by the live API
    try:
        with socket.create_connection(listener.getsockname(), timeout=3) as client:
            verify = ssl.create_default_context(cafile=str(CERTS / 'ca.pem'))
            exchange_connected(client, 'standard-lab.invalid', 'standard-lab.invalid',
                               '/FAKE_PATH?key=FAKE_QUERY', verify, time.monotonic() + 5, out)
    finally:
        thread.join(6)
        listener.close()
    assert not thread.is_alive()
    assert errors == []
    assert len(requests) == 1 and requests[0].startswith(b'HEAD /FAKE_PATH?key=FAKE_QUERY HTTP/1.1\r\n')
    assert out['tls']['hostname'] == 'verified'
    assert out['http_status'] == 200
    assert out['failure_code'] == 'none'
    advanced = out['advanced']
    # This injected loopback exchange is synthetic; facts carry no provenance.
    # Production attribution belongs to the guarded observation, not this socket.
    assert advanced['schema_version'] == 'fortress.head-facts/1'
    assert 'provenance' not in advanced
    assert advanced['observations']['hsts'] == 'disabled'
    assert advanced['observations']['cookies']['count'] == 1
    assert advanced['findings']
    assert all(item['route_id'] == 'head-route-1' for item in advanced['findings'])
    encoded = json.dumps(out)
    for marker in ('FAKE_NONCE_MARKER', 'FAKE_NAME', 'FAKE_COOKIE_MARKER', 'FAKE_PATH', 'FAKE_QUERY'):
        assert marker not in encoded
