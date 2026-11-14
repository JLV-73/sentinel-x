import time
import gzip
import pytest

from app import fortress_discovery_transport as transport
from app import fortress_discovery_policy as policy


class Stream:
    def __init__(self, wire, fragment=3):
        self.wire, self.fragment = wire, fragment
    def settimeout(self, value):
        pass
    def recv(self, size):
        size = min(size, self.fragment)
        result, self.wire = self.wire[:size], self.wire[size:]
        return result


def test_chunked_fragmented_response():
    wire = b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/html\r\n\r\n5\r\nhello\r\n0\r\n\r\n'
    assert transport._read_response(Stream(wire), time.monotonic() + 5) == (200, 5)


def test_chunked_coding_is_case_insensitive():
    wire = b'HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\n0\r\n\r\n'
    assert transport._read_response(Stream(wire), time.monotonic() + 5) == (200, 0)


def test_valid_chunk_extensions_are_accepted():
    wire = b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;note="a\\"b"\r\nx\r\n0;end\r\n\r\n'
    assert transport._read_response(Stream(wire), time.monotonic() + 5) == (200, 1)


def test_partial_response_keeps_status_without_following_redirect():
    calls = []
    def exchange(url, cap, timeout):
        calls.append(url)
        return {'status': 302, 'incomplete': True}
    result = policy.discover_observed('https://example.invalid', ['/'], '/', exchange)
    assert len(calls) == 1
    assert result['pages'][0]['status'] == 302
    assert result['pages'][0]['state'] == 'incomplete'
    assert result['pages'][0]['observations'] is None
    assert result['pages'][0]['findings'] == []
    assert not result['complete']


@pytest.mark.parametrize('fragment', [1, 2, 7, 4096])
def test_chunked_gzip_fragmentations(fragment):
    body = gzip.compress(b'hello')
    wire = (b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n'
            + f'{len(body):x}'.encode() + b'\r\n' + body + b'\r\n0\r\n\r\n')
    assert transport._read_response(Stream(wire, fragment), time.monotonic() + 5) == (200, 5)


@pytest.mark.parametrize('wire', [
    b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 1\r\n\r\n0\r\n\r\n',
    b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx',
    b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nx',

    b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nxy',
    b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nContent-Length: 5\r\n\r\n',
    b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;bad=\x00\r\nx\r\n0\r\n\r\n',
    b'HTTP/1.1 204 OK\r\nContent-Length: 0\r\n\r\n',
    b'HTTP/1.1 200 OK\r\nBad Header: x\r\n\r\n',
])
@pytest.mark.parametrize('fragment', [1, 4096])
def test_ambiguous_or_truncated_frames_rejected(wire, fragment):
    with pytest.raises(ValueError):
        transport._read_response(Stream(wire, fragment), time.monotonic() + 5)


def test_extra_bytes_in_same_read_are_rejected_but_later_bytes_unobservable():
    wire = b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nxy'
    with pytest.raises(ValueError):
        transport._read_response(Stream(wire, 4096), time.monotonic() + 5)
    assert transport._read_response(Stream(wire, 1), time.monotonic() + 5) == (200, 1)


def test_gzip_bomb_is_bounded():
    body = gzip.compress(b'x' * 20000)
    wire = (b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n'
            + f'{len(body):x}'.encode() + b'\r\n' + body + b'\r\n0\r\n\r\n')
    with pytest.raises(transport._BudgetExceeded):
        transport._read_response(Stream(wire), time.monotonic() + 5, max_bytes=100)


def test_partial_contract_reaches_live_validator():
    from app import fortress_discovery_contract as contract
    result = policy.discover_observed('https://example.invalid', ['/'], '/',
        lambda *args: {'status': 200, 'incomplete': True}, _live_paths=True)
    result['provenance'] = 'live'
    result['limits'].remove('lab_only')
    result['diagnostic'] = {'phase': 'parse', 'requests_sent': 1, 'responses_received': 1}
    assert contract.valid_live(result)
    assert result['bytes'] == 0


def test_invalid_headers_never_attest_status():
    event = {'phase': 'unknown', 'requests_sent': 1, 'responses_received': 0}
    token = transport._diagnostic.set(event)
    try:
        with pytest.raises(ValueError):
            transport._read_response(Stream(b'HTTP/1.1 200 OK\r\nBad Header: x\r\n\r\n'), time.monotonic() + 5)
        assert event['responses_received'] == 0 and '_status' not in event
    finally:
        transport._diagnostic.reset(token)


@pytest.mark.parametrize('truncated', [False, True])
def test_owned_tls_chunked_and_partial_attestation(truncated):
    import socket
    import ssl
    import threading
    from pathlib import Path
    certs = Path(transport.__file__).with_name('fortress_mvp_tls')
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(str(certs / 'server.pem'), str(certs / 'server-key.pem'))
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client.load_verify_locations(cafile=str(certs / 'ca.pem'))
    left, right = socket.socketpair()
    wire = b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n' + (b'' if truncated else b'0\r\n\r\n')
    errors = []
    def serve():
        try:
            with server.wrap_socket(left, server_side=True) as conn:
                for i in range(0, len(wire), 3):
                    conn.sendall(wire[i:i + 3])
                try:
                    conn.unwrap().close()
                except (ssl.SSLError, ConnectionResetError, ConnectionAbortedError):
                    pass
        except Exception as exc:
            errors.append(type(exc).__name__)
    thread = threading.Thread(target=serve)
    thread.start()
    event = {'phase': 'unknown', 'requests_sent': 1, 'responses_received': 0}
    token = transport._diagnostic.set(event)
    try:
        with client.wrap_socket(right, server_hostname='standard-lab.invalid', suppress_ragged_eofs=False) as conn:
            if truncated:
                with pytest.raises(ValueError):
                    transport._read_response(conn, time.monotonic() + 5)
            else:
                assert transport._read_response(conn, time.monotonic() + 5) == (200, 5)
        assert event['responses_received'] == 1
        assert event.get('_status') == (200 if truncated else None)
    finally:
        transport._diagnostic.reset(token)
        thread.join(6)
    assert not thread.is_alive() and not errors
