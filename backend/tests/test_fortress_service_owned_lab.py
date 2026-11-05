"""Internal service-to-real-transport lab; no API activation or external traffic.

The public peer is deliberately simulated by the test adapter; the actual socket
is connected only to the fixture's ephemeral 127.0.0.1 listener.
"""
import json
import socket

import pytest

import app.fortress_service as service
from app.fortress_transport import SafeTransport
from owned_lab_helpers import HOST, SIMULATED_IP, SENTINELS, OwnedHTTP, SimulatedPublicPeerAdapter


class CookieLab(OwnedHTTP):
    def serve(self):
        try:
            while not self.stop.is_set():
                try:
                    conn, peer = self.listener.accept()
                except socket.timeout:
                    continue
                self.peers.append(peer)
                try:
                    with conn:
                        conn.settimeout(2)
                        data = b''
                        while b'\r\n\r\n' not in data and len(data) < 8192:
                            chunk = conn.recv(2048)
                            if not chunk:
                                break
                            data += chunk
                        self.requests.append(data)
                        path = data.split(b' ', 2)[1]
                        if path == b'/stop-marker':
                            response = b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'
                        elif path == b'/error-marker':
                            response = b'not-http\r\n\r\n'
                        elif path == b'/partial-marker':
                            response = (b'HTTP/1.1 206 Partial Content\r\n'
                                        b'Set-Cookie: lab-cookie-name-sentinel=lab-cookie-value-sentinel\r\n'
                                        b'Content-Length: 0\r\nConnection: close\r\n\r\n')
                        elif path == b'/headers-marker':
                            response = (b'HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=0\r\n'
                                        b"Content-Security-Policy: default-src 'none'\r\n"
                                        b'X-Content-Type-Options: \r\n'
                                        b'Referrer-Policy: no-referrer\r\nReferrer-Policy: origin\r\n'
                                        b'Set-Cookie: lab-cookie-name-sentinel=lab-cookie-value-sentinel\r\n'
                                        b'Content-Length: 0\r\nConnection: close\r\n\r\n')
                        else:
                            secure = b'' if path == b'/missing-marker' else b'; Secure'
                            response = (b'HTTP/1.1 200 OK\r\nSet-Cookie: lab-cookie-name-sentinel=lab-cookie-value-sentinel' + secure +
                                        b'; HttpOnly; SameSite=Lax\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                        conn.sendall(response)
                except OSError as exc:
                    self.errors.append(type(exc).__name__)
        finally:
            self.listener.close()


def payload(*paths):
    return {'level': 'standard', 'authorized': True, 'routes': [
        {'url': f'http://{HOST}{path}', 'safe_use_confirmed': True,
         'methods': ['GET'], 'cors_get': False, 'parameters': []} for path in paths]}


@pytest.fixture
def lab(monkeypatch):
    owned = CookieLab()
    resolutions, adapters, transports = [], [], []
    def resolver(host, port, *, type):
        assert (host, port, type) == (HOST, 80, socket.SOCK_STREAM)
        resolutions.append(1)
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, '', (SIMULATED_IP, 80))]
    def socket_factory(family, kind, protocol):
        assert (family, kind, protocol) == (socket.AF_INET, socket.SOCK_STREAM, 0)
        adapter = SimulatedPublicPeerAdapter(owned)
        adapters.append(adapter)
        return adapter
    def factory(scope, **kwargs):
        transport = SafeTransport(scope, resolver=resolver, socket_factory=socket_factory,
                                  timeout=2, deadline=8, **kwargs)
        transports.append(transport)
        return transport
    try:
        yield owned, resolutions, adapters, transports, factory
    finally:
        owned.close()


def assert_clean(result, paths):
    text = json.dumps(result)
    for secret in (*SENTINELS, HOST, *paths):
        assert secret not in text
    assert result['complete'] is False
    assert all(f['route'] == '[redacted route]' for f in result['findings'])


def assert_connections(lab, n):
    owned, resolutions, adapters, transports, _ = lab
    assert len(owned.requests) == len(owned.peers) == len(resolutions) == len(adapters) == n
    assert all(a.actual_peer == owned.address and a.actual_peer[0] == '127.0.0.1' for a in adapters)
    assert all(a.getpeername() == (SIMULATED_IP, 80) for a in adapters)
    assert all(p[0] == '127.0.0.1' for p in owned.peers)
    assert not owned.errors
    for request in owned.requests:
        lines = request.lower().split(b'\r\n')
        assert not any(line.startswith((b'cookie:', b'authorization:')) for line in lines)
    return transports


def test_scoped_factory_is_explicit_and_not_global(lab):
    original = service._SafeTransport
    result = service._audit_with_factory(payload('/missing-marker'), factory=lab[4])
    assert service._SafeTransport is original
    assert result['requests_used'] == 1
    assert assert_connections(lab, 1)[0].count == 1


def test_real_response_absence_and_nonprotective_presence(lab):
    paths = ('/headers-marker',)
    result = service._audit_with_factory(payload(*paths), factory=lab[4])
    transports = assert_connections(lab, 1)
    assert transports[0].count == result['requests_used'] == 1
    findings = {f['id']: f for f in result['findings']}
    assert findings['permissions_policy']['status'] == 'attention'
    assert all(findings[k]['status'] == 'indeterminate' for k in
               ('hsts', 'csp', 'x_content_type_options', 'referrer_policy'))
    assert findings['cookie_attributes']['status'] == 'attention'
    assert_clean(result, paths)


def test_real_response_absent_hsts(lab):
    paths = ('/missing-marker',)
    result = service._audit_with_factory(payload(*paths), factory=lab[4])
    assert assert_connections(lab, 1)[0].count == result['requests_used'] == 1
    assert next(f for f in result['findings'] if f['id'] == 'hsts')['status'] == 'indeterminate'
    assert_clean(result, paths)


def test_service_real_transport_cookie_findings(lab):
    paths = ('/missing-marker', '/protected-marker')
    result = service._audit_with_factory(payload(*paths), factory=lab[4])
    transports = assert_connections(lab, 2)
    assert len(transports) == 1 and transports[0].count == result['requests_used'] == 2
    assert [f['status'] for f in result['findings'] if f['id'] == 'cookie_attributes'] == ['attention', 'conformant']
    assert all(f['status'] == 'indeterminate' for f in result['findings'] if f['id'] in ('cors', 'redirect', 'reflection', 'version'))
    assert [r.split(b'\r\n', 1)[0] for r in lab[0].requests] == [b'GET /missing-marker HTTP/1.1', b'GET /protected-marker HTTP/1.1']
    assert_clean(result, paths)


def test_consent_and_private_scope_denied_before_any_socket(lab):
    request = payload('/missing-marker')
    request['authorized'] = 1
    with pytest.raises(service.AuditError):
        service._audit_with_factory(request, factory=lab[4])
    request['authorized'] = True
    request['routes'][0]['url'] = 'http://127.0.0.1/'
    with pytest.raises(service.AuditError):
        service._audit_with_factory(request, factory=lab[4])
    assert assert_connections(lab, 0) == []


@pytest.mark.parametrize('first', ['/stop-marker', '/error-marker', '/partial-marker'])
def test_stop_or_invalid_response_never_claims_findings_or_sends_followup(lab, first):
    paths = (first, '/missing-marker')
    result = service._audit_with_factory(payload(*paths), factory=lab[4])
    transports = assert_connections(lab, 1)
    assert transports[0].count == result['requests_used'] == 1
    assert transports[0].blocked is True
    assert all(f['status'] == 'indeterminate' for f in result['findings'])
    assert_clean(result, paths)
