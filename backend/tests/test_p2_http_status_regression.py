"""Strict HTTP evidence from owned, ephemeral TLS fixtures only."""
import json
import time
import pytest

from app import fortress_service as service
from app.fortress_transport import SafeTransport
from test_fortress_tls_lab import certificates, TLSLab, LocalSocketAdapter, client_context, resolver, HOST


@pytest.mark.parametrize('wire,expected,state', [
    (b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n', 200, 'completed'),
    (b'HTTP/1.1 302 Found\r\nContent-Length: 4\r\n\r\nab', None, 'blocked'),
    (b'HTTP/1.1 302 Found\r\nLocation: https://outside.invalid/secret\r\nContent-Length: 4\r\n\r\nab', None, 'blocked'),
    (b'HTTP/1.1 302 Found\r\nContent-Length: 4\r\n\r\ntest', 302, 'redirected'),
    (b'HTTP/1.1 302 Found\r\nLocation: https://outside.invalid/secret\r\nContent-Length: 0\r\n\r\n', 302, 'redirected'),
    (b'HTTP/1.1 403 Forbidden\r\nSet-Cookie: sid=secret\r\nContent-Length: 4\r\n\r\ndeny', 403, 'indeterminate'),
    (b'HTTP/1.1 403 Forbidden\r\nContent-Length: 4\r\n\r\nde', None, 'blocked'),
    (b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n', None, 'blocked'),
    (b'HTTP/1.1 403 Forbidden\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nde', None, 'blocked'),
])
@pytest.mark.parametrize('language', ['fr', 'en'])
def test_real_strict_status_only_after_complete_frame(certificates, wire, expected, state, language):
    class WireLab(TLSLab):
        def _serve(self):
            try:
                conn, _ = self.listener.accept()
                with conn, self.context.wrap_socket(conn, server_side=True) as tls:
                    while b'\r\n\r\n' not in self.record['request']:
                        data = tls.recv(2048)
                        if not data:
                            return
                        self.record['request'] += data
                    tls.sendall(wire)
            finally:
                self.listener.close()
    lab = WireLab(certificates)
    def factory(scope, **kwargs):
        return SafeTransport(scope, resolver=resolver, socket_factory=lambda *args: LocalSocketAdapter(lab.address, lab.record),
                             tls_context=client_context(certificates / 'ca.pem'), timeout=4, **kwargs)
    try:
        report = service._audit_single_with_factory(json.dumps({'url': f'https://{HOST}/', 'authorized': True, 'method': 'GET'}), factory=factory, language=language)
    finally:
        lab.finish()
    assert report['http_status'] == expected
    assert report['route_execution'][0]['state'] == state
    if expected is not None:
        assert report['failure_code'] == ('http_refused' if expected == 403 else 'none')
    elif b'Transfer-Encoding' not in wire:
        assert report['failure_code'] == 'incomplete'
    else:
        assert report['failure_code'] == 'security_refused'
    assert lab.record['request'].count(b'GET / HTTP/1.1') == 1
    assert all(secret not in repr(report) for secret in ('outside.invalid', 'secret', HOST, 'deny'))
    if state != 'completed':
        assert all(f['status'] == 'indeterminate' for f in report['findings'])


def test_real_timeout_never_fabricates_status(certificates):
    class SlowLab(TLSLab):
        def _serve(self):
            try:
                conn, _ = self.listener.accept()
                with conn, self.context.wrap_socket(conn, server_side=True) as tls:
                    self.record['request'] = tls.recv(2048)
                    time.sleep(.4)
            finally:
                self.listener.close()
    lab = SlowLab(certificates)
    def factory(scope, **kwargs):
        return SafeTransport(scope, resolver=resolver, socket_factory=lambda *args: LocalSocketAdapter(lab.address, lab.record),
                             tls_context=client_context(certificates / 'ca.pem'), timeout=.15, **kwargs)
    try:
        report = service._audit_single_with_factory(json.dumps({'url': f'https://{HOST}/', 'authorized': True, 'method': 'GET'}), factory=factory)
    finally:
        lab.finish()
    assert report['http_status'] is None
    assert report['failure_code'] == 'timeout'
    assert report['route_execution'][0]['state'] == 'blocked'
    assert all(f['status'] == 'indeterminate' for f in report['findings'])



def test_tls_hostname_refusal_never_fabricates_status(certificates):
    lab = TLSLab(certificates)
    def factory(scope, **kwargs):
        return SafeTransport(scope, resolver=resolver, socket_factory=lambda *args: LocalSocketAdapter(lab.address, lab.record),
                             tls_context=client_context(certificates / 'ca.pem'), timeout=4, **kwargs)
    try:
        report = service._audit_single_with_factory(json.dumps({'url': 'https://wrong-fortress-lab.invalid/', 'authorized': True, 'method': 'GET'}), factory=factory)
    finally:
        lab.finish()
    assert report['http_status'] is None
    assert report['route_execution'][0]['state'] == 'blocked'
    assert report['failure_code'] == 'tls_or_transport'
    assert lab.record['request'] == b''
    assert all(f['status'] == 'indeterminate' for f in report['findings'])
