import socket
import ssl
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from app.fortress_live import exchange_connected, observe, result

CERTS = Path(__file__).resolve().parents[1] / 'app' / 'fortress_mvp_tls'


class TransportTests(unittest.TestCase):
    def test_mixed_dns_blocks_before_connect(self):
        rows = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', 443)),
                (socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('::1', 443, 0, 0))]
        with patch('socket.getaddrinfo', return_value=rows), patch('socket.socket') as sock:
            out = observe('https://example.com/private?secret=1')
        self.assertEqual(out['failure_code'], 'blocked')
        self.assertEqual(out['target'], 'https://example.com/')
        sock.assert_not_called()

    def test_private_ipv4_ipv6_and_mapped_rejected(self):
        for host in ('127.0.0.1', '10.0.0.1', '169.254.169.254', '[::1]', '[fc00::1]', '[::ffff:8.8.8.8]'):
            with self.subTest(host=host), self.assertRaises(ValueError):
                from app.fortress_live import validate_url
                validate_url('https://' + host + '/')

    def test_peer_mismatch_is_blocked(self):
        from unittest.mock import MagicMock
        sock = MagicMock()
        sock.getpeername.return_value = ('127.0.0.1', 443)
        rows = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', 443))]
        with patch('socket.getaddrinfo', return_value=rows), patch('socket.socket', return_value=sock):
            out = observe('https://example.com/')
        self.assertEqual(out['failure_code'], 'blocked')
        sock.close.assert_called_once()

    def test_tls_wrong_hostname_fails(self):
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(CERTS / 'server.pem'), str(CERTS / 'server-key.pem'))
        def serve():
            conn, _ = listener.accept()
            try:
                with ctx.wrap_socket(conn, server_side=True):
                    pass
            except ssl.SSLError:
                pass
        thread = threading.Thread(target=serve)
        thread.start()
        client = socket.create_connection(listener.getsockname(), timeout=3)
        verify = ssl.create_default_context(cafile=str(CERTS / 'ca.pem'))
        out = result('https://wrong.invalid/')
        try:
            with self.assertRaises(ssl.SSLCertVerificationError):
                exchange_connected(client, 'wrong.invalid', 'wrong.invalid', '/', verify, time.monotonic() + 3, out)
        finally:
            client.close()
            thread.join(3)
            listener.close()
        self.assertFalse(thread.is_alive())
        self.assertEqual(out['tls']['hostname'], 'indeterminate')

    def test_tls_head_only_requested_path_no_redirect(self):
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        seen = []
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(CERTS / 'server.pem'), str(CERTS / 'server-key.pem'))
        def serve():
            conn, _ = listener.accept()
            with ctx.wrap_socket(conn, server_side=True) as tls:
                seen.append(tls.recv(4096))
                tls.sendall(b'HTTP/1.1 302 Found\r\nLocation: https://example.invalid/secret\r\nContent-Length: 0\r\n\r\n')
        thread = threading.Thread(target=serve)
        thread.start()
        client = socket.create_connection(listener.getsockname(), timeout=3)
        verify = ssl.create_default_context(cafile=str(CERTS / 'ca.pem'))
        out = result('https://standard-lab.invalid/')
        try:
            exchange_connected(client, 'standard-lab.invalid', 'standard-lab.invalid', '/private?secret=1', verify, time.monotonic() + 3, out)
        finally:
            client.close()
            thread.join(3)
            listener.close()
        self.assertFalse(thread.is_alive())
        self.assertEqual(out['http_status'], 302)
        self.assertEqual(out['failure_code'], 'none')
        self.assertEqual(out['tls']['hostname'], 'verified')
        self.assertTrue(seen[0].startswith(b'HEAD /private?secret=1 HTTP/1.1\r\n'))
        self.assertNotIn('secret', str(out))
