"""Loopback-only qualification of the current fail-closed chunked policy.

The injected socket redirects the verified test-only public endpoint to loopback;
it is not a production connector and never sends traffic to the public Internet.
"""
import socket
import threading
import time

import pytest

from app.fortress_transport import SafeTransport, validate_scope

URL = 'http://example.com/'
PUBLIC = '93.184.216.34'


class LoopbackPinnedSocket:
    def __init__(self, port):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.port = port

    def settimeout(self, timeout):
        self.socket.settimeout(timeout)

    def connect(self, address):
        assert address == (PUBLIC, 80)
        self.socket.connect(('127.0.0.1', self.port))

    def getpeername(self):
        assert self.socket.getpeername() == ('127.0.0.1', self.port)
        return (PUBLIC, 80)

    def __getattr__(self, name):
        return getattr(self.socket, name)


@pytest.mark.parametrize('parts', [
    [b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chu', b'nked\r\n\r\n', b'2\r\nOK\r\n0\r\n\r\n'],
    [b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n0\r\n\r\n'],
    [b'HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n'],
    [b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\nOK\r\n0\r\n\r\n'],
    [b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFFFFFFFFFFFFFFFFFF\r\n'],
    [b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nContent-Length: 0\r\n\r\n'],
])
def test_chunked_refusal_latches_and_prevents_second_http(parts):
    requests = []
    errors = []
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(('127.0.0.1', 0))
    listener.listen(2)
    listener.settimeout(1)
    port = listener.getsockname()[1]

    def server():
        try:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(1)
                received = bytearray()
                while b'\r\n\r\n' not in received:
                    data = connection.recv(4096)
                    if not data:
                        raise AssertionError('truncated request')
                    received.extend(data)
                requests.append(bytes(received))
                for part in parts:
                    try:
                        connection.sendall(part)
                        time.sleep(0.005)
                    except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                        break
            try:
                second, _ = listener.accept()
            except socket.timeout:
                return
            with second:
                requests.append(second.recv(4096))
        except Exception as exc:
            errors.append(repr(exc))
        finally:
            listener.close()

    thread = threading.Thread(target=server)
    thread.start()
    resolutions = []

    def resolver(host, target_port, *, type):
        resolutions.append((host, target_port))
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, '', (PUBLIC, 80))]

    transport = SafeTransport(validate_scope(URL, []), resolver=resolver,
                              socket_factory=lambda *_: LoopbackPinnedSocket(port), timeout=1)
    first = transport.observe_headers('GET', URL)
    second = transport.observe_headers('GET', URL)
    thread.join(3)
    assert not thread.is_alive()
    assert not errors
    assert first == {'outcome': 'error'}
    assert second == {'outcome': 'error'}
    assert transport.blocked
    assert resolutions == [('example.com', 80)]
    assert len(requests) == 1
    assert requests[0].startswith(b'GET / HTTP/1.1\r\n')
    assert b'Host: example.com\r\n' in requests[0]
