import unittest
from unittest.mock import patch

from app import fortress_discovery_transport as transport


class TransportTests(unittest.TestCase):
    def test_invalid_path_before_dns(self):
        with patch.object(transport.socket, 'getaddrinfo') as dns:
            result = transport.get('https://example.invalid/delete?token=secret')
        self.assertEqual(result['error'], 'blocked')
        dns.assert_not_called()


import gzip
import socket
import ssl

IP = '8.8.8.8'  # Synthetic fixture; socket creation is mocked.
def row(ip=IP):
    return (socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, 443))

class FakeSocket:
    def __init__(self, response, peer):
        self.response, self.peer, self.sent = response, peer, []
        self.connected, self.closed = None, False
    def settimeout(self, timeout): pass
    def connect(self, address): self.connected = address
    def getpeername(self): return self.peer, 443
    def sendall(self, data): self.sent.append(data)
    def recv(self, count):
        part, self.response = self.response[:count], self.response[count:]
        return part
    def do_handshake(self): pass
    def close(self): self.closed = True
    def __enter__(self): return self
    def __exit__(self, *args): self.close()

class FakeContext:
    def __init__(self, failure=None):
        self.failure, self.hostname = failure, None
    def load_default_certs(self): pass
    def wrap_socket(self, sock, server_hostname, do_handshake_on_connect, suppress_ragged_eofs):
        self.hostname = server_hostname
        self.suppress_ragged_eofs = suppress_ragged_eofs
        if self.failure: raise self.failure
        return sock

class ExchangeTests(unittest.TestCase):
    def invoke(self, response=b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok', rows=None, peer=IP, failure=None):
        sock = FakeSocket(response, peer)
        ctx = FakeContext(failure)
        with patch.object(transport.socket, 'getaddrinfo', return_value=rows if rows is not None else [row()]) as dns, \
             patch.object(transport.socket, 'socket', return_value=sock) as factory, \
             patch.object(transport.ssl, 'SSLContext', return_value=ctx):
            result = transport.get('https://example.invalid/')
        return result, sock, ctx, dns, factory

    def test_success_pins_ip_host_and_tls(self):
        result, sock, ctx, dns, factory = self.invoke()
        self.assertEqual(result, {'error': None, 'status': 200, 'decoded_bytes': 2})
        self.assertEqual(sock.connected, (IP, 443))
        self.assertEqual(ctx.hostname, 'example.invalid')
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)
        self.assertFalse(ctx.suppress_ragged_eofs)
        self.assertEqual(len(sock.sent), 1)
        self.assertIn(b'Host: example.invalid\r\n', sock.sent[0])
        self.assertNotIn(b'Cookie:', sock.sent[0])
        self.assertNotIn(b'Authorization:', sock.sent[0])
        self.assertTrue(sock.closed)
        self.assertEqual(dns.call_count, 1)
        self.assertEqual(factory.call_count, 1)

    def test_mixed_dns_rejected_before_socket(self):
        result, _, _, _, factory = self.invoke(rows=[row(), row('127.0.0.1')])
        self.assertEqual(result['error'], 'blocked')
        factory.assert_not_called()

    def test_peer_rebinding_rejected_before_tls(self):
        result, sock, ctx, _, _ = self.invoke(peer='1.1.1.1')
        self.assertEqual(result['error'], 'blocked')
        self.assertIsNone(ctx.hostname)
        self.assertEqual(sock.sent, [])

    def test_bad_tls_before_request(self):
        result, sock, _, _, _ = self.invoke(failure=ssl.SSLCertVerificationError('SECRET'))
        self.assertEqual(result['error'], 'transport')
        self.assertEqual(sock.sent, [])
        self.assertNotIn('SECRET', repr(result))

    def test_redirect_complete_body_required_no_follow(self):
        result, sock, _, dns, _ = self.invoke(b'HTTP/1.1 302 Found\r\nLocation: https://secret.invalid/\r\nContent-Length: 0\r\n\r\n')
        self.assertEqual(result['status'], 302)
        self.assertEqual(len(sock.sent), 1)
        self.assertEqual(dns.call_count, 1)
        result, *_ = self.invoke(b'HTTP/1.1 302 Found\r\nContent-Length: 4\r\n\r\nx')
        self.assertIsNone(result['status'])

    def test_gzip_bomb_and_wire_budget(self):
        bomb = gzip.compress(b'x' * (512 * 1024 + 1))
        response = b'HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: ' + str(len(bomb)).encode() + b'\r\n\r\n' + bomb
        result, *_ = self.invoke(response)
        self.assertIsNone(result['status'])
        result, *_ = self.invoke(b'HTTP/1.1 200 OK\r\nContent-Length: 524289\r\n\r\n')
        self.assertIsNone(result['status'])

    def test_gzip_exact_limit(self):
        body = gzip.compress(b'x' * (512 * 1024))
        result, *_ = self.invoke(b'HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)
        self.assertEqual(result['decoded_bytes'], 512 * 1024)

    def test_rejects_ambiguous_framing_and_partial(self):
        for headers in (b'Content-Length: 2\r\nTransfer-Encoding: chunked', b'Content-Length: 2\r\nContent-Length: 2', b'Transfer-Encoding: chunked', b'Content-Length: 9'):
            result, *_ = self.invoke(b'HTTP/1.1 200 OK\r\n' + headers + b'\r\n\r\nok')
            self.assertIsNone(result['status'])
        result, *_ = self.invoke(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n')
        self.assertIsNone(result['status'])

    def test_deadline_after_dns_prevents_socket(self):
        with patch.object(transport.socket, 'getaddrinfo', return_value=[row()]), \
             patch.object(transport.socket, 'socket') as factory, \
             patch.object(transport.time, 'monotonic', side_effect=[0, 9]):
            result = transport.get('https://example.invalid/', timeout=8)
        self.assertEqual(result['error'], 'timeout')
        factory.assert_not_called()

    def test_forbidden_paths(self):
        with patch.object(transport.socket, 'getaddrinfo') as dns:
            for path in ('/api/v1', '/%64elete', '/../x', '//foo', '/admin', '/x#fragment'):
                self.assertEqual(transport.get('https://example.invalid' + path)['error'], 'blocked')
        dns.assert_not_called()

    def test_empty_and_nonpublic_dns(self):
        for rows in ([], [row('127.0.0.1')], [row('10.0.0.1')]):
            result, _, _, _, factory = self.invoke(rows=rows)
            self.assertEqual(result['error'], 'blocked')
            factory.assert_not_called()

    def test_invalid_204_and_overlong_headers(self):
        for response in (b'HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n',
                         b'HTTP/1.1 200 OK\r\nX: ' + b'x' * 33000 + b'\r\n\r\n'):
            result, *_ = self.invoke(response)
            self.assertIsNone(result['status'])

    def test_empty_status_framing_and_close(self):
        for status, headers in ((204, b''), (205, b'Content-Length: 0\r\n'), (304, b'')):
            with self.subTest(status=status, headers=headers):
                result, *_ = self.invoke(b'HTTP/1.1 ' + str(status).encode() + b' Empty\r\n' + headers + b'\r\n')
                self.assertEqual(result, {'error': None, 'status': status, 'decoded_bytes': 0})
        # A fake socket cannot attest an authenticated TLS close_notify.
        result, *_ = self.invoke(b'HTTP/1.1 205 Reset Content\r\n\r\n')
        self.assertEqual(result['error'], 'blocked')
        for headers in (b'Content-Length: 1\r\n', b'Content-Length: 0\r\nContent-Length: 0\r\n',
                        b'Transfer-Encoding: chunked\r\n', b'Content-Encoding: identity\r\n'):
            with self.subTest(headers=headers):
                result, *_ = self.invoke(b'HTTP/1.1 205 Reset Content\r\n' + headers + b'\r\n')
                self.assertEqual(result['error'], 'blocked')

    def test_fragmented_body_and_excess_or_clean_close(self):
        for last, expected in ((b'', None), (b'x', None), (TimeoutError(), None),
                               (ssl.SSLEOFError(), None)):
            with self.subTest(last=last), patch.object(FakeSocket, 'recv', side_effect=[
                    b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n', b'o', b'k', last]):
                result, *_ = self.invoke()
                self.assertEqual(result['error'], expected)
                if expected is None:
                    self.assertEqual(result['decoded_bytes'], 2)

    def test_205_rejects_nonempty_body(self):
        result, *_ = self.invoke(b'HTTP/1.1 205 Reset Content\r\nContent-Length: 2\r\n\r\nok')
        self.assertEqual(result['error'], 'blocked')

    def test_later_extra_bytes_are_not_read_and_socket_is_closed(self):
        for header in (b'HTTP/1.1 204 No Content\r\n\r\n',
                       b'HTTP/1.1 205 Reset Content\r\nContent-Length: 0\r\n\r\n',
                       b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok'):
            with self.subTest(header=header), patch.object(FakeSocket, 'recv', side_effect=[header, b'x', b'']) as receive:
                result, sock, *_ = self.invoke()
                self.assertIsNone(result['error'])
                self.assertEqual(receive.call_count, 1)
                self.assertTrue(sock.closed)

    def test_no_wait_for_close_after_complete_response(self):
        for header in (b'HTTP/1.1 204 No Content\r\n\r\n',
                       b'HTTP/1.1 205 Reset Content\r\nContent-Length: 0\r\n\r\n',
                       b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n'):
            with self.subTest(header=header), patch.object(FakeSocket, 'recv', side_effect=[header, TimeoutError()]) as receive:
                result, *_ = self.invoke()
                self.assertIsNone(result['error'])
                self.assertEqual(receive.call_count, 1)

    def test_empty_status_body_in_same_fragment_rejected(self):
        for status in (204, 205):
            result, *_ = self.invoke(b'HTTP/1.1 ' + str(status).encode() + b' Empty\r\n\r\nx')
            self.assertEqual(result['error'], 'blocked')

    def test_timeout_during_receive(self):
        with patch.object(FakeSocket, 'recv', side_effect=TimeoutError('SECRET')):
            result, *_ = self.invoke()
        self.assertEqual(result['error'], 'timeout')
        self.assertNotIn('SECRET', repr(result))

if __name__ == '__main__': unittest.main()
