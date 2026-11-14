import unittest
from unittest.mock import patch
import gzip
import errno
import ipaddress
import socket
import ssl
import threading
from pathlib import Path

from app import fortress_discovery_transport as transport
from test_discovery_transport import FakeSocket, FakeContext, row, IP


class ExchangeContractTests(unittest.TestCase):
    def test_http_external_base_network_reference_is_excluded_by_policy(self):
        from app import fortress_discovery_policy as policy
        body = b'<base href="http://outside.invalid/docs/"><a href="//example.invalid/guide">'
        response = (b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: '
                    + str(len(body)).encode() + b'\r\n\r\n' + body)
        sock = FakeSocket(response, IP)
        with patch.object(transport.socket, 'getaddrinfo', return_value=[row()]) as dns, \
             patch.object(transport.socket, 'socket', return_value=sock) as sockets, \
             patch.object(transport.ssl, 'SSLContext', return_value=FakeContext()):
            result = policy.discover_observed('https://example.invalid', ['/', '/guide'], '/', transport.exchange_observed)
        self.assertEqual(result['requests'], 1)
        self.assertEqual(result['exclusion_reasons']['unknown'], 1)
        self.assertEqual(dns.call_count, 1)
        self.assertEqual(sockets.call_count, 1)
        self.assertNotIn('outside.invalid', repr(result))

    def test_network_reference_document_base_matrix(self):
        origin = 'https://example.invalid/dir/page'
        cases = (
            ('<a href="//example.invalid/guide">', ['//example.invalid/guide']),
            ('<base href="https://example.invalid/docs/"><a href="//example.invalid/guide">', ['https://example.invalid/guide']),
            ('<base href="https://example.invalid/docs/"><a href="//outside.invalid/guide">', [None]),
            ('<base href="http://example.invalid/docs/"><a href="//example.invalid/guide">', [None]),
            ('<base href="http://outside.invalid/docs/"><a href="//example.invalid/guide">', [None]),
            ('<base href="https://outside.invalid/docs/"><a href="//example.invalid/guide">', [None]),
            ('<base href="http://[bad"><a href="//example.invalid/guide">', [None]),
            ('<base href="ftp://example.invalid/"><a href="//example.invalid/guide">', [None]),
            ('<base href="http://outside.invalid/"><a href="https://example.invalid/guide"><a href="http://example.invalid/guide">', ['https://example.invalid/guide', None]),
            ('<a href="//example.invalid/guide"><base href="http://outside.invalid/"><base href="https://example.invalid/">', [None]),
            ('<a href="//example.invalid/guide"><base href="https://example.invalid/"><base href="http://outside.invalid/">', ['https://example.invalid/guide']),
        )
        for document, expected in cases:
            with self.subTest(document=document):
                parser = transport._Links(origin, report_excluded=True)
                parser.feed(document)
                parser.close()
                self.assertEqual(parser.links, expected)

    def test_https_base_network_reference_reaches_allowed_route(self):
        from app import fortress_discovery_policy as policy
        body = b'<a href="//example.invalid/guide"><base href="https://example.invalid/docs/">'
        response = (b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: '
                    + str(len(body)).encode() + b'\r\n\r\n' + body)
        sockets = [FakeSocket(response, IP), FakeSocket(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n', IP)]
        now = [0.0]
        with patch.object(transport.socket, 'getaddrinfo', return_value=[row()]) as dns, \
             patch.object(transport.socket, 'socket', side_effect=sockets), \
             patch.object(transport.ssl, 'SSLContext', side_effect=lambda *a: FakeContext()):
            result = policy.discover('https://example.invalid', ['/', '/guide'], '/', transport.exchange,
                                     clock=lambda: now[0], sleep=lambda n: now.__setitem__(0, now[0] + n))
        self.assertTrue(result['complete'])
        self.assertEqual(result['requests'], 2)
        self.assertIn(b'GET /guide HTTP/1.1', sockets[1].sent[0])
        self.assertTrue(all(call.args[0] == 'example.invalid' for call in dns.call_args_list))

    def test_html_base_resolves_earlier_relative_anchor(self):
        body = b'<a href="guide">go</a><base href="/docs/">'
        response = (b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: '
                    + str(len(body)).encode() + b'\r\n\r\n' + body)
        result = self.invoke(response)
        self.assertEqual(result['links'], ['https://example.invalid/docs/guide'])

    def test_malformed_https_base_does_not_invent_local_destination(self):
        parser = transport._Links('https://example.invalid/dir/page', report_excluded=True)
        parser.feed('<base href="https:fake/"><a href="item">')
        self.assertEqual(parser.links, [None])

    def test_html_base_variants_and_excluded_schemes(self):
        def links(document, url='https://example.invalid/dir/page'):
            parser = transport._Links(url, report_excluded=True)
            # Fragment boundaries include the base element itself.
            for chunk in (document[:19], document[19:37], document[37:]):
                parser.feed(chunk)
            parser.close()
            return parser.links

        absolute = 'https://example.invalid/safe'
        cases = [
            ('<a href="x"></a><base href="sub/"><base href="/ignored/">', ['https://example.invalid/dir/sub/x']),
            ('<base><base href="/chosen/"><a href="x">', ['https://example.invalid/chosen/x']),
            ('<base href=""><base href="/ignored/"><a href="x">', ['https://example.invalid/dir/x']),
            ('<base href="https://outside.invalid/secret/"><a href="x"><a href="/x"><a href="https://example.invalid/safe">', [None, None, absolute]),
            ('<base href="http://outside.invalid/"><a href="x"><a href="https://example.invalid/safe">', [None, absolute]),
            ('<base href="http://[bad"><a href="x"><a href="https://example.invalid/safe">', [None, absolute]),
            ('<base href="/one/" href="/two/"><a href="x"><a href="https://example.invalid/safe">', [None, absolute]),
            ('<base href="/docs/"><a href="javascript:alert(1)"><a href="//outside.invalid/x"><a href="/admin"><a href="/x?SECRET">', [None, None, None, None]),
            ('<base href="../unsafe/"><a href="x"><a href="https://example.invalid/safe">', [None, absolute]),
        ]
        for document, expected in cases:
            with self.subTest(document=document):
                result = links(document)
                self.assertEqual(result, expected)
                self.assertNotIn('SECRET', repr(result))
                self.assertNotIn('outside.invalid', repr(result))

    def test_external_base_chunked_policy_never_resolves_external_dns(self):
        from app import fortress_discovery_policy as policy
        body = (b'<a href="fake">BEFORE</a><base href="https://outside.invalid/secret/">'
                b'<a href="/fake">ROOT</a><a href="https://example.invalid/allowed">OK</a>')
        parts = [body[:20], body[20:47], body[47:]]
        chunked = b''.join(('%x\r\n' % len(part)).encode() + part + b'\r\n' for part in parts) + b'0\r\n\r\n'
        first = b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n' + chunked
        second = b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n'
        sockets = [FakeSocket(first, IP), FakeSocket(second, IP)]
        now = [0.0]
        with patch.object(transport.socket, 'getaddrinfo', return_value=[row()]) as dns, \
             patch.object(transport.socket, 'socket', side_effect=sockets), \
             patch.object(transport.ssl, 'SSLContext', side_effect=lambda *a: FakeContext()):
            result = policy.discover('https://example.invalid', ['/', '/allowed', '/fake'], '/', transport.exchange,
                                     clock=lambda: now[0], sleep=lambda n: now.__setitem__(0, now[0] + n))
        self.assertTrue(result['complete'])
        self.assertEqual(result['pages'], 2)
        self.assertEqual(dns.call_count, 2)
        self.assertTrue(all(call.args[0] == 'example.invalid' for call in dns.call_args_list))
        self.assertIn(b'GET /allowed HTTP/1.1', sockets[1].sent[0])
        self.assertNotIn('outside.invalid', repr(result))
        self.assertNotIn('secret', repr(result))

    def test_redirect_then_base_uses_final_document_url(self):
        from app import fortress_discovery_policy as policy
        redirect = b'HTTP/1.1 302 Found\r\nLocation: /dir/page\r\nContent-Length: 0\r\n\r\n'
        body = b'<a href="next">x</a><base href="docs/">'
        page = (b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: '
                + str(len(body)).encode() + b'\r\n\r\n' + body)
        final = b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n'
        sockets = [FakeSocket(response, IP) for response in (redirect, page, final)]
        now = [0.0]
        with patch.object(transport.socket, 'getaddrinfo', return_value=[row()]) as dns, \
             patch.object(transport.socket, 'socket', side_effect=sockets), \
             patch.object(transport.ssl, 'SSLContext', side_effect=lambda *a: FakeContext()):
            result = policy.discover('https://example.invalid', ['/', '/dir/page', '/dir/docs/next'], '/',
                                     transport.exchange, clock=lambda: now[0],
                                     sleep=lambda n: now.__setitem__(0, now[0] + n))
        self.assertTrue(result['complete'])
        self.assertEqual(result['pages'], 2)
        self.assertEqual(result['requests'], 3)
        self.assertIn(b'GET /dir/docs/next HTTP/1.1', sockets[2].sent[0])
        self.assertTrue(all(call.args[0] == 'example.invalid' for call in dns.call_args_list))

    def test_observed_external_base_exclusions_are_counted_without_disclosure(self):
        from app import fortress_discovery_policy as policy
        body = b'<a href="x">x</a><base href="https://outside.invalid/SECRET/"><a href="/y">y</a>'
        response = (b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: '
                    + str(len(body)).encode() + b'\r\n\r\n' + body)
        sock = FakeSocket(response, IP)
        with patch.object(transport.socket, 'getaddrinfo', return_value=[row()]) as dns, \
             patch.object(transport.socket, 'socket', return_value=sock), \
             patch.object(transport.ssl, 'SSLContext', return_value=FakeContext()):
            result = policy.discover_observed('https://example.invalid', ['/'], '/', transport.exchange_observed)
        self.assertEqual(result['exclusion_reasons']['unknown'], 2)
        self.assertEqual(dns.call_count, 1)
        self.assertNotIn('outside.invalid', repr(result))
        self.assertNotIn('SECRET', repr(result))

    def test_base_does_not_weaken_link_count_limit(self):
        parser = transport._Links('https://example.invalid/', report_excluded=True)
        with self.assertRaises(ValueError):
            parser.feed('<base href="/docs/">' + '<a href="x">' * 1001)

    def test_returns_extracted_links_not_body(self):
        body = b'<p>BODY_SECRET</p><a href="/next">go</a>'
        response = (b'HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: '
                    + str(len(body)).encode() + b'\r\n\r\n' + body)
        sock, ctx = FakeSocket(response, IP), FakeContext()
        with patch.object(transport.socket, 'getaddrinfo', return_value=[row()]), \
             patch.object(transport.socket, 'socket', return_value=sock), \
             patch.object(transport.ssl, 'SSLContext', return_value=ctx):
            result = transport.exchange('https://example.invalid/', 1000, 8)
        self.assertEqual(result, {'status': 200, 'decoded_bytes': len(body), 'links': ['/next'], 'location': None})
        self.assertNotIn('BODY_SECRET', repr(result))

    def invoke(self, response, cap=1000):
        sock = FakeSocket(response, IP)
        with patch.object(transport.socket, 'getaddrinfo', return_value=[row()]), \
             patch.object(transport.socket, 'socket', return_value=sock), \
             patch.object(transport.ssl, 'SSLContext', return_value=FakeContext()):
            return transport.exchange('https://example.invalid/', cap, 8)

    def test_budget_and_gzip(self):
        for encoded in (False, True):
            body = b'0123456789'
            wire = gzip.compress(body) if encoded else body
            headers = b'Content-Encoding: gzip\r\n' if encoded else b''
            response = b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n' + headers + b'Content-Length: ' + str(len(wire)).encode() + b'\r\n\r\n' + wire
            self.assertEqual(self.invoke(response, 9), {})
            self.assertEqual(self.invoke(response, 10)['decoded_bytes'], 10)

    def test_external_link_does_not_hide_internal_link(self):
        for href in (b'https://outside.invalid/', b'http://outside.invalid/', b'//outside.invalid/'):
            with self.subTest(href=href):
                body = b'<a href="' + href + b'">external</a><a href="/next">internal</a>'
                response = b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body
                result = self.invoke(response)
                self.assertEqual(result['links'], ['/next'])
                self.assertNotIn('outside.invalid', repr(result))

    def test_invalid_references_never_exposed(self):
        for href in (b'/next#SECRET', b'/next?SECRET', b'/../next'):
            body = b'<a href="' + href + b'">x</a>'
            response = b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body
            self.assertEqual(self.invoke(response), {})

    def test_redirect_validated_and_not_followed(self):
        response = b'HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n'
        self.assertEqual(self.invoke(response)['location'], '/next')
        response = b'HTTP/1.1 302 Found\r\nLocation: /next?SECRET\r\nContent-Length: 0\r\n\r\n'
        self.assertIsNone(self.invoke(response)['location'])

    def test_external_redirect_is_blocked_without_following(self):
        from app import fortress_discovery_policy as policy
        response = b'HTTP/1.1 302 Found\r\nLocation: https://outside.invalid/secret\r\nContent-Length: 0\r\n\r\n'
        sock = FakeSocket(response, IP)
        with patch.object(transport.socket, 'getaddrinfo', return_value=[row()]) as dns, \
             patch.object(transport.socket, 'socket', return_value=sock) as sockets, \
             patch.object(transport.ssl, 'SSLContext', return_value=FakeContext()):
            result = policy.discover('https://example.invalid', ['/'], '/', transport.exchange)
        self.assertEqual(result['reason'], 'redirect_blocked')
        self.assertFalse(result['complete'])
        self.assertEqual(result['requests'], 1)
        self.assertEqual(dns.call_count, 1)
        self.assertEqual(sockets.call_count, 1)
        self.assertNotIn('secret', repr(result))
        self.assertNotIn('outside.invalid', repr(result))

    def test_policy_consumes_transport_metadata(self):
        from app import fortress_discovery_policy as policy
        body = b'<a href="/next">go</a>'
        first = b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body
        second = b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n'
        sockets = [FakeSocket(first, IP), FakeSocket(second, IP)]
        now = [0.0]
        with patch.object(transport.socket, 'getaddrinfo', return_value=[row()]), \
             patch.object(transport.socket, 'socket', side_effect=sockets), \
             patch.object(transport.ssl, 'SSLContext', side_effect=lambda *a: FakeContext()):
            result = policy.discover('https://example.invalid', ['/', '/next'], '/', transport.exchange,
                                     clock=lambda: now[0], sleep=lambda n: now.__setitem__(0, now[0]+n))
        self.assertTrue(result['complete'])
        self.assertEqual(result['pages'], 2)
        self.assertNotIn('/next', repr(result))


class RealTlsFixtureTests(unittest.TestCase):
    def test_certificate_and_hostname_fail_before_http(self):
        certs = Path(transport.__file__).with_name('fortress_mvp_tls')
        for host, trust_ca in (('standard-lab.invalid', False), ('wrong-lab.invalid', True)):
            with self.subTest(host=host, trust_ca=trust_ca):
                server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                server_context.load_cert_chain(str(certs / 'server.pem'), str(certs / 'server-key.pem'))
                listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                listener.bind(('127.0.0.1', 0))
                listener.listen(1)
                listener.settimeout(4)
                port = listener.getsockname()[1]
                observations = []
                verification_errors = []
                original_handshake = ssl.SSLSocket.do_handshake
                def capture_handshake(sock, *args, **kwargs):
                    try:
                        return original_handshake(sock, *args, **kwargs)
                    except ssl.SSLCertVerificationError as exc:
                        verification_errors.append((exc.verify_code, exc.verify_message))
                        raise
                def server():
                    try:
                        with listener.accept()[0] as conn:
                            conn.settimeout(4)
                            observations.append(('accepted', None))
                            try:
                                tls = server_context.wrap_socket(conn, server_side=True)
                            except ssl.SSLError as exc:
                                observations.append(('handshake_ssl_error', exc))
                                return
                            except ConnectionResetError as exc:
                                observations.append(('handshake_reset', exc))
                                return
                            with tls:
                                try:
                                    observations.append(('http', tls.recv(4096)))
                                except ssl.SSLError as exc:
                                    observations.append(('read_ssl_error', exc))
                    except OSError as exc:
                        observations.append(('unexpected_socket_error', exc))
                thread = threading.Thread(target=server)
                thread.start()
                try:
                    def load_fixture_ca(ctx):
                        if trust_ca:
                            ctx.load_verify_locations(cafile=str(certs / 'ca.pem'))
                    with patch.object(transport, '_resolve', return_value=(socket.AF_INET, '127.0.0.1')), \
                         patch.object(transport, 'public_ip', side_effect=ipaddress.ip_address), \
                         patch.object(ssl.SSLContext, 'load_default_certs', load_fixture_ca), \
                         patch.object(ssl.SSLSocket, 'do_handshake', capture_handshake):
                        result = transport.exchange('https://' + host + ':' + str(port) + '/', 1000, 5)
                finally:
                    listener.close()
                    thread.join(6)
                self.assertFalse(thread.is_alive())
                self.assertEqual(result, {})
                self.assertEqual([code for code, _ in verification_errors], [62 if trust_ca else 20], verification_errors)
                self.assertEqual(len(observations), 2, observations)
                self.assertEqual(observations[0], ('accepted', None))
                event, value = observations[1]
                # A verified client rejection can surface as a TLS alert or a
                # reset during the server handshake (not an accept/read error).
                self.assertIn(event, ('handshake_ssl_error', 'handshake_reset', 'read_ssl_error', 'http'), observations)
                if event == 'handshake_reset':
                    self.assertIn(value.errno, (errno.ECONNRESET, 10054))
                elif event == 'http':
                    self.assertEqual(value, b'', observations)

    def test_verified_tls_fragmented_response(self):
        certs = Path(transport.__file__).with_name('fortress_mvp_tls')
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(str(certs / 'server.pem'), str(certs / 'server-key.pem'))
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(4)
        port = listener.getsockname()[1]
        requests = []
        def server():
            try:
                with listener.accept()[0] as conn:
                    conn.settimeout(4)
                    with server_context.wrap_socket(conn, server_side=True) as tls:
                        request = b''
                        while b'\r\n\r\n' not in request:
                            request += tls.recv(4096)
                        requests.append(request)
                        body = b'<a href="/next">SECRET_BODY</a>'
                        response = b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body
                        for i in range(0, len(response), 7):
                            tls.sendall(response[i:i+7])
                        tls.unwrap().close()
            except (OSError, ssl.SSLError):
                pass
        thread = threading.Thread(target=server)
        thread.start()
        try:
            # Exceptions are confined to this owned fixture; production accepts none.
            with patch.object(transport, '_resolve', return_value=(socket.AF_INET, '127.0.0.1')), \
                 patch.object(transport, 'public_ip', side_effect=ipaddress.ip_address), \
                 patch.object(ssl.SSLContext, 'load_default_certs',
                              lambda ctx: ctx.load_verify_locations(cafile=str(certs / 'ca.pem'))):
                result = transport.exchange('https://standard-lab.invalid:' + str(port) + '/', 1000, 5)
        finally:
            listener.close()
            thread.join(6)
        self.assertFalse(thread.is_alive())
        self.assertEqual(result['links'], ['/next'])
        self.assertNotIn('SECRET_BODY', repr(result))
        self.assertEqual(len(requests), 1)
        self.assertIn(b'GET / HTTP/1.1\r\nHost: standard-lab.invalid:', requests[0])
