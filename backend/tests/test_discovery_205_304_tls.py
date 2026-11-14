import socket
import ssl
import threading
import time
from pathlib import Path

import pytest
from app import fortress_discovery_transport as transport

CERTS = Path(transport.__file__).with_name('fortress_mvp_tls')


def exchange(wire, mode='hold', timeout=0.25, project=False):
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(str(CERTS / 'server.pem'), str(CERTS / 'server-key.pem'))
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client.load_verify_locations(cafile=str(CERTS / 'ca.pem'))
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    sent, release = threading.Event(), threading.Event()
    errors = []
    def serve():
        try:
            with listener, listener.accept()[0] as raw:
                with server.wrap_socket(raw, server_side=True) as tls:
                    assert tls.recv(4096).startswith(b'GET / ')
                    tls.sendall(wire)
                    sent.set()
                    if mode == 'clean':
                        try:
                            tls.unwrap().close()
                        except (ssl.SSLError, OSError):
                            pass
                    elif mode == 'hold':
                        release.wait(3)
        except Exception as exc:
            errors.append(repr(exc))
    thread = threading.Thread(target=serve)
    thread.start()
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=2) as raw:
            with client.wrap_socket(raw, server_hostname='standard-lab.invalid', suppress_ragged_eofs=False) as tls:
                tls.sendall(b'GET / HTTP/1.1\r\nHost: standard-lab.invalid\r\n\r\n')
                assert sent.wait(2)
                return transport._read_response(tls, time.monotonic() + timeout, project=project, base='https://standard-lab.invalid/')
    finally:
        release.set()
        thread.join(4)
        assert not thread.is_alive() and not errors, errors


@pytest.mark.parametrize('headers,body', [
    (b'Content-Length: 0\r\n', b''),
    (b'Transfer-Encoding: chunked\r\n', b'0\r\n\r\n'),
])
def test_205_self_delimited_returns_without_close(headers, body):
    assert exchange(b'HTTP/1.1 205 Reset Content\r\n' + headers + b'\r\n' + body) == (205, 0)


def test_205_without_framing_waits_for_clean_tls_close():
    wire = b'HTTP/1.1 205 Reset Content\r\n\r\n'
    with pytest.raises(TimeoutError):
        exchange(wire)
    assert exchange(wire, mode='clean') == (205, 0)


def test_205_timeout_attests_partial_headers():
    event = {}
    token = transport._diagnostic.set(event)
    try:
        with pytest.raises(TimeoutError):
            exchange(b'HTTP/1.1 205 Reset Content\r\nStrict-Transport-Security: secret\r\n\r\n')
    finally:
        transport._diagnostic.reset(token)
    assert event['_status'] == 205
    assert event['_partial_headers']['present'] == ['strict-transport-security']
    assert 'secret' not in repr(event)


def test_205_abrupt_tls_close_is_not_complete():
    with pytest.raises(ssl.SSLError):
        exchange(b'HTTP/1.1 205 Reset Content\r\n\r\n', mode='abrupt')


@pytest.mark.parametrize('headers,body,mode', [
    (b'Transfer-Encoding: chunked\r\n', b'1\r\nx\r\n0\r\n\r\n', 'hold'),
    (b'', b'x', 'clean'),
    (b'Content-Length: 1\r\n', b'x', 'hold'),
    (b'Content-Length: 0\r\nTransfer-Encoding: chunked\r\n', b'0\r\n\r\n', 'hold'),
])
def test_205_rejects_content_or_ambiguous_framing(headers, body, mode):
    with pytest.raises(ValueError):
        exchange(b'HTTP/1.1 205 Reset Content\r\n' + headers + b'\r\n' + body, mode=mode)


@pytest.mark.parametrize('headers', [
    b'Content-Length: 123\r\nContent-Encoding: br\r\n',
    b'Transfer-Encoding: gzip, chunked\r\nContent-Encoding: gzip\r\n',
    b'Transfer-Encoding: chunked\r\n',
])
def test_304_metadata_returns_without_body_or_links(headers):
    result = exchange(b'HTTP/1.1 304 Not Modified\r\n' + headers + b'Content-Type: text/html\r\nLocation: /other\r\n\r\n', project='observed')
    assert result[:4] == (304, 0, [], None)


@pytest.mark.parametrize('headers,body', [
    (b'Content-Length: 1\r\nTransfer-Encoding: chunked\r\n', b''),
    (b'Transfer-Encoding: chunked, gzip\r\n', b''),
    (b'Content-Length: nope\r\n', b''),
    (b'Content-Length: 3\r\n', b'bad'),
])
def test_304_rejects_ambiguous_invalid_or_observed_body(headers, body):
    with pytest.raises(ValueError):
        exchange(b'HTTP/1.1 304 Not Modified\r\n' + headers + b'\r\n' + body)


@pytest.mark.parametrize('headers', [b'Content-Length: 0\r\n', b'Transfer-Encoding: chunked\r\n'])
def test_204_forbids_framing(headers):
    with pytest.raises(ValueError):
        exchange(b'HTTP/1.1 204 No Content\r\n' + headers + b'\r\n')
