"""Internal-only integration against an owned TLS listener; no public network."""
import json
import socket
import pytest

from app import fortress_service as service
from app.fortress_transport import SafeTransport
from app.fortress_single_scope import SingleScopeError, prepare_single_scope
from app.fortress_standard_contract import _project
from test_fortress_tls_lab import (certificates, TLSLab, LocalSocketAdapter,
                                    client_context, resolver, HOST)


def test_single_scope_real_tls_one_get(certificates, monkeypatch):
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **k: (_ for _ in ()).throw(AssertionError('DNS forbidden')))
    lab = TLSLab(certificates)
    def factory(scope, **kwargs):
        return SafeTransport(scope, resolver=resolver,
            socket_factory=lambda *args: LocalSocketAdapter(lab.address, lab.record),
            tls_context=client_context(certificates / 'ca.pem'), timeout=4, **kwargs)
    try:
        report = service._audit_single_with_factory(
            json.dumps({'url': f'https://{HOST}/', 'authorized': True, 'method': 'GET'}),
            factory=factory)
    finally:
        lab.finish()
    assert report['requests_used'] == 1
    assert report['route_execution'] == [{'route_index': 1, 'state': 'completed'}]
    assert lab.record['request'].count(b'GET / HTTP/1.1') == 1
    assert lab.record['sni'] == [HOST]
    assert next(f for f in report['findings'] if f['id'] == 'https_tls')['status'] == 'conformant'
    assert HOST not in repr(report)


@pytest.mark.parametrize('header,expected,code', [
    (b'nosniff', 'conformant', 'header_valid'),
    (b'other', 'attention', 'header_invalid'),
])
def test_real_header_value_facts(certificates, header, expected, code):
    class HeaderLab(TLSLab):
        def _serve(self):
            try:
                conn, _ = self.listener.accept()
                with conn, self.context.wrap_socket(conn, server_side=True) as tls:
                    while b'\r\n\r\n' not in self.record['request']:
                        data = tls.recv(2048)
                        if not data: return
                        self.record['request'] += data
                    tls.sendall(b'HTTP/1.1 200 OK\r\nX-Content-Type-Options: ' + header + b'\r\nContent-Length: 0\r\n\r\n')
            finally:
                self.listener.close()
    lab = HeaderLab(certificates)
    def factory(scope, **kwargs):
        return SafeTransport(scope, resolver=resolver, socket_factory=lambda *args: LocalSocketAdapter(lab.address, lab.record),
                             tls_context=client_context(certificates / 'ca.pem'), timeout=4, **kwargs)
    try:
        report = service._audit_single_with_factory(json.dumps({'url': f'https://{HOST}/', 'authorized': True, 'method': 'GET'}), factory=factory)
    finally:
        lab.finish()
    finding = next(f for f in report['findings'] if f['id'] == 'x_content_type_options')
    assert (finding['status'], finding['evidence_code']) == (expected, code)


@pytest.mark.parametrize('headers,expected', [
    (b'Strict-Transport-Security: max-age=3600\r\nContent-Security-Policy: default-src \'none\'\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: unsafe-url\r\nPermissions-Policy: camera=()\r\n',
     [('indeterminate', 'header_syntax_recognized'), ('indeterminate', 'header_syntax_recognized'), ('conformant', 'header_valid'), ('indeterminate', 'header_syntax_recognized'), ('indeterminate', 'header_syntax_recognized')]),
    (b'Strict-Transport-Security: max-age=0\r\nContent-Security-Policy: \r\nX-Content-Type-Options: other\r\nReferrer-Policy: \r\nPermissions-Policy: \r\n',
     [('attention', 'header_invalid')] * 5),
    (b'Strict-Transport-Security: unusual\r\nContent-Security-Policy: unusual\r\nX-Content-Type-Options: a b\r\nReferrer-Policy: unusual\r\nPermissions-Policy: unusual\r\n',
     [('indeterminate', 'indeterminate')] * 5),
    (b'', [('attention', 'header_absent')] * 5),
])
def test_real_five_header_categories(certificates, headers, expected):
    class HeaderLab(TLSLab):
        def _serve(self):
            try:
                conn, _ = self.listener.accept()
                with conn, self.context.wrap_socket(conn, server_side=True) as tls:
                    while b'\r\n\r\n' not in self.record['request']:
                        data = tls.recv(2048)
                        if not data:
                            return
                        self.record['request'] += data
                    tls.sendall(b'HTTP/1.1 200 OK\r\n' + headers + b'Content-Length: 0\r\n\r\n')
            finally:
                self.listener.close()
    lab = HeaderLab(certificates)
    def factory(scope, **kwargs):
        return SafeTransport(scope, resolver=resolver, socket_factory=lambda *args: LocalSocketAdapter(lab.address, lab.record),
                             tls_context=client_context(certificates / 'ca.pem'), timeout=4, **kwargs)
    try:
        report = service._audit_single_with_factory(json.dumps({'url': f'https://{HOST}/', 'authorized': True, 'method': 'GET'}), factory=factory)
    finally:
        lab.finish()
    names = ('hsts', 'csp', 'x_content_type_options', 'referrer_policy', 'permissions_policy')
    findings = {f['id']: f for f in report['findings']}
    assert report['http_status'] == 200
    assert [(findings[n]['status'], findings[n]['evidence_code']) for n in names] == expected
    assert HOST not in repr(report)


def test_consent_rejected_before_factory():
    called = []
    with pytest.raises(SingleScopeError):
        service._audit_single_with_factory(json.dumps({'url': f'https://{HOST}/', 'authorized': False, 'method': 'GET'}), factory=lambda *a, **k: called.append(1))
    assert called == []


@pytest.mark.parametrize('outcome,redirected,blocked', [
    ('indeterminate', False, False), ('ok', True, False), ('ok', False, True),
])
def test_uncompleted_observations_cannot_project_headers(outcome, redirected, blocked):
    class IncompleteTransport:
        def __init__(self, *args, **kwargs):
            self.count, self.blocked = 0, False
        def observe_headers(self, method, url):
            self.count += 1
            self.blocked = blocked
            return {'outcome': outcome, 'redirected': redirected, 'status': 302 if redirected else 200,
                    'security_headers': dict.fromkeys(('hsts', 'csp', 'x_content_type_options', 'referrer_policy', 'permissions_policy'), 'present'),
                    'header_value_facts': {'x_content_type_options': 'recognized_nosniff'}}
    report = service._audit_single_with_factory(json.dumps({'url': f'https://{HOST}/', 'authorized': True, 'method': 'GET'}), factory=IncompleteTransport)
    assert report['route_execution'][0]['state'] != 'completed'
    names = {'hsts', 'csp', 'x_content_type_options', 'referrer_policy', 'permissions_policy'}
    assert all(f['status'] == f['evidence_code'] == 'indeterminate' for f in report['findings'] if f['id'] in names)


@pytest.mark.parametrize('status,redirected,outcome,blocked', [
    (302, False, 'ok', False), (300, False, 'ok', False),
    (304, False, 'ok', False), (302, True, 'ok', False),
    (200, True, 'ok', False), (99, False, 'ok', False),
    (600, False, 'ok', False), (None, False, 'ok', False),
    (206, False, 'ok', False), (403, False, 'ok', False),
    (200, False, 'indeterminate', False), (200, False, 'ok', True),
])
def test_strict_inconsistent_observation_never_manufactures_findings(status, redirected, outcome, blocked):
    class InconsistentTransport:
        def __init__(self, *args, **kwargs):
            self.count, self.blocked = 0, False
        def observe_headers(self, method, url):
            assert method == 'GET'
            self.count += 1
            self.blocked = blocked
            return {'status': status, 'redirected': redirected, 'outcome': outcome,
                    'tls': {'certificate': 'verified', 'protocol': 'TLSv1.3'},
                    'cookies': {'count': 1, 'missing_secure': 0, 'missing_httponly': 0,
                                'missing_samesite': 0, 'indeterminate': 0},
                    'security_headers': {'x_content_type_options': 'present'},
                    'header_value_facts': {'x_content_type_options': 'recognized_nosniff'}}
    report = service._audit_single_with_factory(
        json.dumps({'url': f'https://{HOST}/', 'authorized': True, 'method': 'GET'}),
        factory=InconsistentTransport)
    assert report['route_execution'][0]['state'] != 'completed'
    assert all(f['status'] == 'indeterminate' for f in report['findings'])
    assert HOST not in repr(report)


def _fake_header_report(security, derived):
    class FakeTransport:
        def __init__(self, *args, **kwargs):
            self.count, self.blocked = 0, False
        def observe_headers(self, method, url):
            self.count += 1
            return {'status': 200, 'redirected': False, 'outcome': 'ok',
                    'tls': {'certificate': 'verified', 'protocol': 'TLSv1.3'},
                    'security_headers': {'x_content_type_options': security, 'csp': 'absent'},
                    'header_value_facts': {'x_content_type_options': derived}}
    return service._audit_single_with_factory(
        json.dumps({'url': f'https://{HOST}/', 'authorized': True, 'method': 'GET'}),
        factory=FakeTransport)


@pytest.mark.parametrize('security,derived', [
    ('absent', 'recognized_nosniff'), ('invalid', 'recognized_nosniff'),
    ('present', 'absent'), ('absent', 'other_token'), ('present', 'invalid'),
])
def test_conflicting_header_categories_are_indeterminate(security, derived):
    report = _fake_header_report(security, derived)
    findings = {f['id']: f for f in report['findings']}
    assert (findings['x_content_type_options']['status'], findings['x_content_type_options']['evidence_code']) == ('indeterminate', 'indeterminate')
    assert (findings['csp']['status'], findings['csp']['evidence_code']) == ('attention', 'header_absent')
    assert findings['https_tls']['status'] == 'conformant'


@pytest.mark.parametrize('security,derived', [('unknown', 'recognized_nosniff'), ('present', 'unknown'),
                                               ('nonsense', 'recognized_nosniff'), ('present', ['recognized_nosniff'])])
def test_unknown_or_invalid_header_categories_do_not_claim_conformance(security, derived):
    report = _fake_header_report(security, derived)
    finding = next(f for f in report['findings'] if f['id'] == 'x_content_type_options')
    assert (finding['status'], finding['evidence_code']) == ('indeterminate', 'indeterminate')


@pytest.mark.parametrize('security,derived,expected', [
    ('present', 'recognized_nosniff', ('conformant', 'header_valid')),
    ('absent', 'absent', ('attention', 'header_absent')),
    ('invalid', 'invalid', ('attention', 'header_invalid')),
    ('unknown', 'other_token', ('attention', 'header_invalid')),
    ('unknown', 'unknown', ('indeterminate', 'indeterminate')),
])
def test_consistent_header_categories_retain_truthful_findings(security, derived, expected):
    report = _fake_header_report(security, derived)
    finding = next(f for f in report['findings'] if f['id'] == 'x_content_type_options')
    assert (finding['status'], finding['evidence_code']) == expected


def test_real_redirect_is_not_followed_or_exposed(certificates):
    class RedirectLab(TLSLab):
        def _serve(self):
            try:
                conn, _ = self.listener.accept()
                with conn, self.context.wrap_socket(conn, server_side=True) as tls:
                    while b'\r\n\r\n' not in self.record['request']:
                        data = tls.recv(2048)
                        if not data: return
                        self.record['request'] += data
                    tls.sendall(b'HTTP/1.1 302 Found\r\nLocation: https://outside.invalid/secret\r\nSet-Cookie: sid=secret; Secure\r\nContent-Length: 0\r\n\r\n')
            finally:
                self.listener.close()
    lab = RedirectLab(certificates)
    def factory(scope, **kwargs):
        return SafeTransport(scope, resolver=resolver, socket_factory=lambda *args: LocalSocketAdapter(lab.address, lab.record),
                             tls_context=client_context(certificates / 'ca.pem'), timeout=4, **kwargs)
    raw = json.dumps({'url': f'https://{HOST}/', 'authorized': True, 'method': 'GET'})
    try:
        report = service._audit_single_with_factory(raw, factory=factory, language='fr')
    finally:
        lab.finish()
    assert report['http_status'] == 302 and report['requests_used'] == 1
    assert report['route_execution'][0]['state'] == 'redirected'
    assert lab.record['request'].count(b'GET / HTTP/1.1') == 1
    assert all(s not in repr(report) for s in ('outside.invalid', 'secret', HOST))
    assert all(f['status'] == 'indeterminate' for f in report['findings'])
    with pytest.raises(ValueError):
        _project(report, prepare_single_scope(raw))  # projection rejects this new schema


def test_certificate_hostname_mismatch_no_http(certificates):
    lab = TLSLab(certificates)
    def factory(scope, **kwargs):
        return SafeTransport(scope, resolver=resolver, socket_factory=lambda *args: LocalSocketAdapter(lab.address, lab.record),
                             tls_context=client_context(certificates / 'ca.pem'), timeout=4, **kwargs)
    try:
        report = service._audit_single_with_factory(json.dumps({'url': 'https://wrong-fortress-lab.invalid/', 'authorized': True, 'method': 'GET'}), factory=factory)
    finally:
        lab.finish()
    assert lab.record['sni'] == ['wrong-fortress-lab.invalid']
    assert lab.record['request'] == b''
    assert report['route_execution'][0]['state'] == 'blocked'
    assert all(f['status'] == 'indeterminate' for f in report['findings'])
