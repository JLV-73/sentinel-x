import gzip
import ipaddress
import socket
import ssl
import threading
from pathlib import Path

import pytest
from app import fortress_discovery_transport as transport

CERTS = Path(transport.__file__).with_name('fortress_mvp_tls')


def run_exchange(monkeypatch, body, mode='clean', *, cap=4096, encoding=b'', timeout=1, version=b'1.1', tls_version=None):
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(str(CERTS / 'server.pem'), str(CERTS / 'server-key.pem'))
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client.load_verify_locations(cafile=str(CERTS / 'ca.pem'))
    if tls_version is not None:
        server.minimum_version = server.maximum_version = tls_version
        client.minimum_version = client.maximum_version = tls_version
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    listener.settimeout(3)
    port = listener.getsockname()[1]
    sent, release = threading.Event(), threading.Event()
    errors = []
    def serve():
        try:
            raw, _ = listener.accept()
            with server.wrap_socket(raw, server_side=True) as tls:
                tls.settimeout(3)
                request = b''
                while b'\r\n\r\n' not in request:
                    chunk = tls.recv(4096)
                    if not chunk:
                        raise AssertionError('request truncated')
                    request += chunk
                assert request.startswith(b'GET / HTTP/1.1\r\n')
                tls.sendall(b'HTTP/' + version + b' 200 OK\r\nContent-Type: text/html\r\nStrict-Transport-Security: SECRET_HEADER\r\n' + encoding + b'\r\n' + body)
                sent.set()
                if mode == 'clean':
                    try:
                        tls.unwrap().close()
                    except (ssl.SSLError, OSError):
                        pass  # Client can close after receiving close_notify.
                elif mode == 'hold':
                    assert release.wait(4)
                # Otherwise close the TCP socket without TLS shutdown.
        except Exception as exc:
            errors.append(repr(exc))
        finally:
            listener.close()
    thread = threading.Thread(target=serve)
    thread.start()
    monkeypatch.setattr(transport, '_resolve', lambda host, p: (socket.AF_INET, '127.0.0.1'))
    monkeypatch.setattr(transport, 'public_ip', ipaddress.ip_address)
    class ClientContext:
        verify_mode = ssl.CERT_REQUIRED
        check_hostname = True
        def load_default_certs(self):
            pass  # Only the test CA is trusted by the preconfigured client.
        def wrap_socket(self, *args, **kwargs):
            return client.wrap_socket(*args, **kwargs)
    monkeypatch.setattr(transport.ssl, 'SSLContext', lambda protocol: ClientContext())
    try:
        result, event = transport.capture_observed(f'https://standard-lab.invalid:{port}/', cap, timeout)
        assert sent.is_set()
    finally:
        release.set()
        thread.join(5)
    assert not thread.is_alive() and not errors, errors
    assert 'SECRET_HEADER' not in repr((result, event))
    return result, event


@pytest.mark.parametrize('version', [b'1.0', b'1.1'])
def test_clean_close_delimited_tls_is_complete(monkeypatch, version):
    result, event = run_exchange(monkeypatch, b'<p>hello</p>', version=version)
    assert result['status'] == 200 and result['decoded_bytes'] == 12
    assert not result.get('incomplete') and event['phase'] == 'none'


def test_close_delimited_gzip_complete_and_truncated(monkeypatch):
    member = gzip.compress(b'<p>hello</p>')
    result, event = run_exchange(monkeypatch, member, encoding=b'Content-Encoding: gzip\r\n')
    assert result['decoded_bytes'] == 12 and event['phase'] == 'none'
    monkeypatch.undo()
    result, event = run_exchange(monkeypatch, member[:-3], encoding=b'Content-Encoding: gzip\r\n')
    assert result['status'] == 200 and result['incomplete'] and event['phase'] == 'parse'


@pytest.mark.parametrize('tls_version', [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3])
@pytest.mark.parametrize('mode,phase', [('abrupt', 'unknown'), ('hold', 'timeout')])
def test_abrupt_or_held_tls_preserves_partial(monkeypatch, mode, phase, tls_version):
    result, event = run_exchange(monkeypatch, b'<p>SECRET_BODY', mode, timeout=0.3, tls_version=tls_version)
    assert result == {'status': 200, 'incomplete': True, 'partial_headers': {
        'present': ['strict-transport-security'], 'completeness': 'headers_validated_body_incomplete'}}
    assert event['phase'] == phase and event['responses_received'] == 1
    assert 'SECRET_BODY' not in repr((result, event))


def test_close_delimited_gzip_bounded(monkeypatch):
    result, event = run_exchange(monkeypatch, gzip.compress(b'x' * 10000), cap=100,
                                 encoding=b'Content-Encoding: gzip\r\n')
    assert result['incomplete'] and result['status'] == 200 and event['phase'] == 'budget'


def test_close_delimited_wire_limit(monkeypatch):
    # A valid gzip member with an oversized optional filename: almost no
    # decoded bytes, so the wire limit is exercised independently.
    monkeypatch.setattr(transport, '_MAX', 256)
    member = bytearray(gzip.compress(b'x'))
    member[3] = 8  # FNAME
    body = bytes(member[:10]) + b'a' * 300 + b'\x00' + bytes(member[10:])
    result, event = run_exchange(monkeypatch, body, cap=256,
                                 encoding=b'Content-Encoding: gzip\r\n')
    assert result['incomplete'] and result['status'] == 200 and event['phase'] == 'budget'
