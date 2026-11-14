"""Offline TLS evidence slice; not an end-to-end worker test."""
import json
import socket
import ssl
import threading
import unittest
from pathlib import Path

from app import fortress_discovery_transport as transport


def tls_projection(hsts, status=200):
    certs = Path(transport.__file__).with_name('fortress_mvp_tls')
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(str(certs / 'server.pem'), str(certs / 'server-key.pem'))
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client.load_verify_locations(cafile=str(certs / 'ca.pem'))
    left, right = socket.socketpair()
    body = b'' if status == 204 else b'SECRET_BODY_997'
    framing = b'' if status == 204 else b'Content-Length: ' + str(len(body)).encode() + b'\r\n'
    headers = (b'HTTP/1.1 ' + str(status).encode() + b' OK\r\nContent-Type: text/html\r\n' + framing +
               b'Strict-Transport-Security: ' + hsts +
               b'\r\nContent-Security-Policy: script-src \'nonce-SECRET_NONCE_997\'\r\n'
               b'Set-Cookie: SECRET_NAME_997=SECRET_COOKIE_997; Secure; HttpOnly\r\n\r\n')
    errors = []
    def respond():
        try:
            with server.wrap_socket(left, server_side=True) as conn:
                conn.sendall(headers + body)
                try:
                    conn.unwrap().close()
                except ssl.SSLEOFError:
                    pass
        except Exception as exc:
            errors.append(type(exc).__name__)
    thread = threading.Thread(target=respond)
    thread.start()
    try:
        import time
        with client.wrap_socket(right, server_hostname='standard-lab.invalid', suppress_ragged_eofs=False) as conn:
            result = transport._read_response(conn, time.monotonic() + 5, project='evidence', base='https://standard-lab.invalid/SECRET_PATH_997')
    finally:
        thread.join(6)
    assert not thread.is_alive()
    assert not errors, errors
    return result


class EvidenceSliceTests(unittest.TestCase):
    def test_tls_statuses_are_retained_and_non_success_is_not_analysed(self):
        for status in (204, 302, 403):
            with self.subTest(status=status):
                result = tls_projection(b'max-age=0', status)
                self.assertEqual(result['status'], status)
                if status != 204:
                    self.assertIsNone(result['evidence'])
                else:
                    self.assertEqual(result['evidence']['hsts'], 'disabled')

    def test_tls_header_evidence_changes_without_disclosing_sensitive_material(self):
        disabled = tls_projection(b'max-age=0')
        enabled = tls_projection(b'max-age=31536000')
        self.assertEqual(disabled['evidence']['hsts'], 'disabled')
        self.assertEqual(enabled['evidence']['hsts'], 'positive')
        self.assertEqual(enabled['evidence']['csp'], 'present')
        self.assertEqual(enabled['evidence']['cookies']['state'], 'observed')
        for result in (disabled, enabled):
            serialized = json.dumps(result)
            for marker in ('SECRET_PATH_997', 'SECRET_BODY_997', 'SECRET_NAME_997', 'SECRET_COOKIE_997', 'SECRET_NONCE_997'):
                self.assertNotIn(marker, serialized)
            self.assertLess(len(serialized), 2048)
