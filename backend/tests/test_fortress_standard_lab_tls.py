"""TLS integration through the fixed, isolated laboratory scenario."""
import ssl
import socket
import pytest
from test_fortress_standard_chain import lab, server, post


def test_local_tls_negotiates_verified_hostname_and_mutated_response(server, monkeypatch):
    wraps = []
    original_wrap = ssl.SSLContext.wrap_socket
    def observe(context, sock, *args, **kwargs):
        wrapped = original_wrap(context, sock, *args, **kwargs)
        if not kwargs.get('server_side', False):
            wraps.append((context.verify_mode, context.check_hostname, kwargs.get('server_hostname'), wrapped.version(), bool(wrapped.getpeercert())))
        return wrapped
    monkeypatch.setattr(ssl.SSLContext, 'wrap_socket', observe)
    original_response = lab._fixture_response
    status, before = post(server, {'scenario': 'positive', 'route_authorized': True})
    assert status == 200
    monkeypatch.setattr(lab, '_fixture_response', lambda scenario: original_response('negative'))
    status, after = post(server, {'scenario': 'positive', 'route_authorized': True})
    assert status == 200
    cookie = lambda report: next(f['status'] for f in report['findings'] if f['id'] == 'cookie_attributes')
    assert (cookie(before), cookie(after)) == ('conformant', 'attention')
    assert len(wraps) == 2
    assert all(v == ssl.CERT_REQUIRED and h and name == 'standard-lab.invalid' and version in ('TLSv1.2', 'TLSv1.3') and cert for v, h, name, version, cert in wraps)


@pytest.mark.parametrize('failure', ['untrusted_ca', 'wrong_hostname'])
def test_failed_verification_sends_no_http(server, monkeypatch, failure):
    sent = []
    errors = []
    listeners = []
    original_init = lab.FixtureSocket.__init__
    def capture_listener(self, listener):
        listeners.append(listener)
        original_init(self, listener)
    monkeypatch.setattr(lab.FixtureSocket, '__init__', capture_listener)
    original_wrap = ssl.SSLContext.wrap_socket
    original_send = ssl.SSLSocket.sendall
    def observe_send(sock, data, *args, **kwargs):
        sent.append(data)
        return original_send(sock, data, *args, **kwargs)
    def wrap(context, sock, *args, **kwargs):
        if not kwargs.get('server_side', False) and failure == 'wrong_hostname':
            kwargs['server_hostname'] = 'wrong.invalid'
        try:
            return original_wrap(context, sock, *args, **kwargs)
        except ssl.SSLCertVerificationError as exc:
            errors.append(exc.verify_message)
            raise
    monkeypatch.setattr(ssl.SSLSocket, 'sendall', observe_send)
    monkeypatch.setattr(ssl.SSLContext, 'wrap_socket', wrap)
    if failure == 'untrusted_ca':
        monkeypatch.setattr(ssl.SSLContext, 'load_verify_locations', lambda *a, **kw: None)
    else:
        # Test-only: accept arbitrary SNI so certificate hostname verification,
        # rather than the separate production SNI guard, is exercised.
        monkeypatch.setattr(ssl.SSLContext, 'set_servername_callback', lambda *a, **kw: None)
    status, body = post(server, {'scenario': 'positive', 'route_authorized': True})
    assert status == 503 and body == {}
    assert errors and ('hostname mismatch' in errors[0].lower() if failure == 'wrong_hostname' else 'issuer' in errors[0].lower() or 'self-signed' in errors[0].lower())
    assert not sent
    assert len(listeners) == 1 and listeners[0].fileno() == -1


def test_scenario_only_connects_loopback_without_dns(monkeypatch):
    connections = []
    listeners = []
    original_init = lab.FixtureSocket.__init__
    def capture_listener(self, listener):
        listeners.append(listener)
        original_init(self, listener)
    monkeypatch.setattr(lab.FixtureSocket, '__init__', capture_listener)
    original_connect = socket.socket.connect
    def only_loopback(sock, address):
        assert address[0] == '127.0.0.1'
        connections.append(address)
        return original_connect(sock, address)
    monkeypatch.setattr(socket.socket, 'connect', only_loopback)
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **k: pytest.fail('real DNS forbidden'))
    for scenario in ('positive', 'negative', 'indeterminate'):
        result = lab.run_scenario(scenario)
        assert result['requests_used'] == 1
        assert 'lab-secret' not in str(result) and lab.HOST not in str(result)
    assert len(connections) == 3
    assert len(listeners) == 3 and all(listener.fileno() == -1 for listener in listeners)
