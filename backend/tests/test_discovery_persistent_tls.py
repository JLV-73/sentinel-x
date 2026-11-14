import socket
import ssl
import threading
import time
from pathlib import Path

import pytest
from app import fortress_discovery_transport as transport

CERTS = Path(transport.__file__).with_name('fortress_mvp_tls')


@pytest.mark.parametrize('wire,expected', [
    (b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello', (200, 5)),
    (b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n', (200, 5)),
    (b'HTTP/1.1 204 No Content\r\n\r\n', (204, 0)),
    (b'HTTP/1.1 205 Reset Content\r\nContent-Length: 0\r\n\r\n', (205, 0)),
    (b'HTTP/1.1 304 Not Modified\r\n\r\n', (304, 0)),
], ids=['length', 'chunked', '204', '205', '304'])
def test_complete_response_returns_before_tls_server_closes(wire, expected):
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(str(CERTS / 'server.pem'), str(CERTS / 'server-key.pem'))
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client.load_verify_locations(cafile=str(CERTS / 'ca.pem'))
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    sent, release, ended = threading.Event(), threading.Event(), threading.Event()
    errors = []
    def serve():
        try:
            with listener, listener.accept()[0] as raw:
                with server.wrap_socket(raw, server_side=True) as tls:
                    assert tls.recv(4096).startswith(b'GET / HTTP/1.1\r\n')
                    tls.sendall(wire)
                    sent.set()
                    release.wait(3)
        except Exception as exc:
            errors.append(repr(exc))
        finally:
            ended.set()
    thread = threading.Thread(target=serve)
    thread.start()
    try:
        with socket.create_connection(listener.getsockname(), timeout=2) as raw:
            with client.wrap_socket(raw, server_hostname='standard-lab.invalid', suppress_ragged_eofs=False) as tls:
                tls.sendall(b'GET / HTTP/1.1\r\nHost: standard-lab.invalid\r\nConnection: keep-alive\r\n\r\n')
                assert sent.wait(1)
                start = time.perf_counter()
                result = transport._read_response(tls, time.monotonic() + 0.5)
                elapsed = time.perf_counter() - start
                print(f'\nTLS {expected}: {elapsed * 1000:.2f} ms; server still open={not ended.is_set()}')
                assert result == expected
                assert elapsed < 0.5
                assert not ended.is_set()
    finally:
        release.set()
        thread.join(4)
    assert ended.is_set() and not errors


@pytest.mark.parametrize('wire', [
    b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nxy',
    b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\ny',
    b'HTTP/1.1 204 No Content\r\n\r\ny',
    b'HTTP/1.1 205 Reset Content\r\n\r\ny',
    b'HTTP/1.1 304 Not Modified\r\n\r\ny',
    b'HTTP/1.1 200 OK\r\n\r\nclose-delimited-not-supported',
])
def test_excess_in_same_read_or_close_delimited_rejected(wire):
    from test_discovery_http_partial import Stream
    with pytest.raises(ValueError):
        transport._read_response(Stream(wire, 4096), time.monotonic() + 1)


@pytest.mark.parametrize('wire', [
    b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nx',
    b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n',
])
def test_delayed_incomplete_message_expires(wire):
    class Delayed:
        def __init__(self): self.first = True
        def settimeout(self, value): self.timeout = value
        def recv(self, count):
            if self.first:
                self.first = False
                return wire
            time.sleep(self.timeout)
            raise TimeoutError()
    with pytest.raises(TimeoutError):
        transport._read_response(Delayed(), time.monotonic() + 0.03)
