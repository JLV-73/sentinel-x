import pytest


def test_rejects_credentialed_url_before_network():
    from app.fortress_transport import validate_scope
    with pytest.raises(ValueError):
        validate_scope('https://user:secret@example.com/', [])

import io
import socket
from unittest.mock import Mock
from app.fortress_transport import SafeTransport, TransportError, validate_scope

URL = 'http://example.com/'
PUBLIC = '93.184.216.34'

def answer(ip=PUBLIC, port=80):
    family = socket.AF_INET6 if ':' in ip else socket.AF_INET
    return (family, socket.SOCK_STREAM, 0, '', (ip, port, 0, 0) if family == socket.AF_INET6 else (ip, port))

class FakeSocket:
    def __init__(self, payload=b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK', peer=(PUBLIC, 80)):
        self.payload, self.peer = payload, peer
        self.sent, self.connected = [], []
    def settimeout(self, value): pass
    def connect(self, where): self.connected.append(where)
    def getpeername(self): return self.peer
    def sendall(self, data): self.sent.append(data)
    def makefile(self, mode): return io.BytesIO(self.payload)
    def close(self): pass

def build(payload=None, peer=(PUBLIC, 80), addresses=None, **kwargs):
    sock = FakeSocket(peer=peer) if payload is None else FakeSocket(payload, peer)
    resolver = Mock(return_value=addresses if addresses is not None else [answer()])
    factory = Mock(return_value=sock)
    transport = SafeTransport(validate_scope(URL, []), resolver=resolver, socket_factory=factory, **kwargs)
    return transport, sock, resolver, factory

@pytest.mark.parametrize('url', [
    'https://user:secret@example.com/', 'http://127.0.0.1/',
    'http://2130706433/', 'http://0177.0.0.1/', 'http://0x7f000001/',
    'http://[::ffff:127.0.0.1]/', 'http://[2002:7f00:1::]/', 'http://[3fff::1]/',
    'http://192.88.99.1/', 'http://192.0.0.9/', 'http://localhost/',
    'http://example.com:81/', 'http://example.com:/', 'http://example.com/#frag',
    'http://example.com/%2fadmin', 'http://example.com/../x',
    'http://example.com/\r\nX:foo', 'http://example.com/?api_key=secret',
    'http://example.com\\@evil.com/', 'http://example.com./',
])
def test_bad_urls_fail_before_dns(url):
    with pytest.raises(ValueError): validate_scope(url, [])

def test_mixed_dns_fails_before_connect():
    transport, sock, resolver, factory = build(addresses=[answer(), answer('127.0.0.1')])
    with pytest.raises(TransportError): transport.request('GET', URL)
    factory.assert_not_called()
    assert not sock.sent

def test_peer_mismatch_fails_before_bytes():
    transport, sock, resolver, factory = build(peer=('127.0.0.1', 80))
    with pytest.raises(TransportError): transport.request('GET', URL)
    assert not sock.sent
    assert resolver.call_count == 1

def test_public_pinned_socket_host_and_no_secrets():
    transport, sock, resolver, factory = build(payload=b'HTTP/1.1 200 OK\r\nSet-Cookie: sid=secret; HttpOnly\r\nContent-Length: 2\r\n\r\nOK')
    result = transport.request('GET', URL)
    assert sock.connected == [(PUBLIC, 80)]
    assert resolver.call_count == 1
    assert b'Host: example.com\r\n' in sock.sent[0]
    assert b'Cookie:' not in sock.sent[0] and b'Authorization:' not in sock.sent[0]
    assert 'secret' not in repr(result.headers)
    assert result.body == b'OK'

@pytest.mark.parametrize('location', ['http://evil.com/', 'http://example.com:443/', '/not-allowed', 'http://127.0.0.1/'])
def test_redirect_refused_before_second_dns(location):
    payload = ('HTTP/1.1 302 Found\r\nLocation: ' + location + '\r\nContent-Length: 0\r\n\r\n').encode()
    transport, sock, resolver, factory = build(payload)
    with pytest.raises(TransportError): transport.request('GET', URL)
    assert resolver.call_count == 1

def test_disallowed_redirect_latches_halt():
    transport, sock, resolver, factory = build(
        b'HTTP/1.1 302 Found\r\nLocation: https://witness.invalid/\r\nContent-Length: 0\r\n\r\n')
    with pytest.raises(TransportError):
        transport.request('GET', URL)
    assert transport.blocked
    with pytest.raises(TransportError):
        transport.request('GET', URL)
    assert resolver.call_count == 1


@pytest.mark.parametrize('status', [401, 403, 429])
def test_block_halts_subsequent_requests(status):
    transport, sock, resolver, factory = build(f'HTTP/1.1 {status} Nope\r\nContent-Length: 0\r\n\r\n'.encode())
    assert transport.request('GET', URL).blocked
    with pytest.raises(TransportError): transport.request('GET', URL)
    assert resolver.call_count == 1

@pytest.mark.parametrize('status,header', [(401, ''), (403, ''), (429, ''), (200, 'CF-Mitigated: challenge\r\n'), (200, 'X-Sucuri-Block: yes\r\n')])
def test_header_blocks_halt_without_reading_body(status, header, monkeypatch):
    import http.client
    def forbidden(*args, **kwargs):
        raise AssertionError('body read after security block')
    monkeypatch.setattr(http.client.HTTPResponse, 'read1', forbidden)
    payload = f'HTTP/1.1 {status} Result\r\n{header}Content-Length: 999999\r\n\r\n'.encode()
    transport, sock, resolver, factory = build(payload)
    assert transport.request('GET', URL).blocked
    with pytest.raises(TransportError):
        transport.request('GET', URL)
    assert resolver.call_count == 1


def test_waf_halts_subsequent_requests():
    transport, sock, resolver, factory = build(b'HTTP/1.1 200 OK\r\nCF-Mitigated: challenge\r\nContent-Length: 0\r\n\r\n')
    assert transport.request('GET', URL).blocked
    with pytest.raises(TransportError): transport.request('GET', URL)

def test_request_quota_includes_each_attempt():
    transport, sock, resolver, factory = build(max_requests=1)
    transport.request('GET', URL)
    with pytest.raises(TransportError): transport.request('GET', URL)
    assert resolver.call_count == 1

def test_large_response_fails_and_halts():
    transport, sock, resolver, factory = build(b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n1234', max_bytes=3)
    with pytest.raises(TransportError): transport.request('GET', URL)
    with pytest.raises(TransportError): transport.request('GET', URL)
    assert resolver.call_count == 1

def test_tls_failure_sends_no_http_and_halts():
    scope = validate_scope('https://example.com/', [])
    sock = FakeSocket(peer=(PUBLIC, 443))
    ctx = Mock(verify_mode=2, check_hostname=True)
    ctx.wrap_socket.side_effect = OSError('bad certificate')
    resolver = Mock(return_value=[answer(port=443)])
    transport = SafeTransport(scope, resolver=resolver, socket_factory=Mock(return_value=sock), tls_context=ctx)
    with pytest.raises(TransportError): transport.request('GET', 'https://example.com/')
    with pytest.raises(TransportError): transport.request('GET', 'https://example.com/')
    assert not sock.sent and resolver.call_count == 1

def test_network_exception_does_not_expose_sensitive_cause():
    import traceback
    transport, sock, resolver, factory = build()
    resolver.side_effect = OSError('dns-secret-sentinel')
    try:
        transport.request('GET', URL)
    except TransportError:
        rendered = traceback.format_exc()
    else:
        pytest.fail('network failure must be rejected')
    assert 'dns-secret-sentinel' not in rendered
    with pytest.raises(TransportError):
        transport.request('GET', URL)
    assert resolver.call_count == 1


def test_invalid_request_headers_and_method_never_resolve():
    transport, sock, resolver, factory = build()
    for method, headers in [('POST', {}), ('GET', {'Authorization': 'secret'}), ('GET', {'Cookie': 'secret'}), ('GET', {'Origin': 'x\r\nHost: evil'})]:
        with pytest.raises(TransportError): transport.request(method, URL, headers)
    resolver.assert_not_called()

@pytest.mark.parametrize('ip', ['::ffff:93.184.216.34', '2002:5db8:d822::1', '2001:0000:4136:e378:8000:63bf:3fff:fdd2', '192.88.99.1'])
def test_special_dns_answers_are_rejected(ip):
    transport, sock, resolver, factory = build(addresses=[answer(ip)])
    with pytest.raises(TransportError): transport.request('GET', URL)
    factory.assert_not_called()

def test_preapproved_redirect_resolves_once_per_hop_and_counts_both():
    first = FakeSocket(b'HTTP/1.1 302 Found\r\nLocation: /two\r\nContent-Length: 0\r\n\r\n')
    second = FakeSocket()
    resolver = Mock(return_value=[answer()])
    factory = Mock(side_effect=[first, second])
    transport = SafeTransport(validate_scope(URL, ['http://example.com/two']), resolver=resolver, socket_factory=factory)
    result = transport.request('GET', URL)
    assert result.status == 200 and result.body == b'OK'
    assert transport.count == resolver.call_count == 2
    assert b'GET /two HTTP/1.1\r\n' in second.sent[0]

def test_concurrent_requests_cannot_exceed_audit_budget():
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event, Lock

    transport, sock, resolver, factory = build(max_requests=1)
    first_entered, second_entered = Event(), Event()
    gate = Lock()
    calls = 0
    remaining = transport._remaining

    def controlled_remaining():
        nonlocal calls
        with gate:
            calls += 1
            number = calls
        if number == 1:
            first_entered.set()
            second_entered.wait(0.5)
        elif number == 2:
            second_entered.set()
        return remaining()

    transport._remaining = controlled_remaining
    def run():
        try:
            return transport.request('GET', URL).status
        except TransportError:
            return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(run)
        assert first_entered.wait(2)
        second = pool.submit(run)
        outcomes = [first.result(timeout=3), second.result(timeout=3)]
    assert sorted(outcomes, key=lambda x: x is None) == [200, None]
    assert transport.count == resolver.call_count == len(sock.sent) == 1


def test_observe_returns_only_derived_cookie_facts_without_secrets():
    payload = (b'HTTP/1.1 200 OK\r\nX-Leak: header-secret\r\n'
               b'Set-Cookie: name-secret=value-secret; Secure; HttpOnly; SameSite=Lax\r\n'
               b'Set-Cookie: another-secret=value-secret\r\nContent-Length: 11\r\n\r\nbody-secret')
    transport, _, _, _ = build(payload)
    result = transport.observe('GET', URL)
    assert result['outcome'] == 'ok'
    assert result['cookies'] == {'count': 2, 'missing_secure': 1, 'missing_httponly': 1, 'missing_samesite': 1, 'indeterminate': 0}
    assert 'secret' not in repr(result) and 'example.com' not in repr(result)


def test_authorized_inert_probe_and_unapproved_probe():
    scope = validate_scope('http://example.com/?q=original', [])
    sock = FakeSocket(b'HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\nFORTRESSINERT2026')
    resolver = Mock(return_value=[answer()])
    transport = SafeTransport(scope, resolver=resolver, socket_factory=Mock(return_value=sock),
                              approved_probes={'http://example.com/?q=original': ['q']})
    assert transport.observe_probe('http://example.com/?q=original', 'other', 'reflection') == {'outcome': 'error'}
    assert resolver.call_count == 0
    # An error latches the audit; use a fresh instance for the valid case.
    assert transport.observe_probe('http://example.com/?q=original', 'q', 'reflection') == {'outcome': 'error'}
    transport = SafeTransport(scope, resolver=resolver, socket_factory=Mock(return_value=sock), approved_probes={'http://example.com/?q=original': ['q']})
    result = transport.observe_probe('http://example.com/?q=original', 'q', 'reflection')
    assert result['reflected'] is True
    assert b'GET /?q=FORTRESSINERT2026 HTTP/1.1' in sock.sent[0]
    assert 'original' not in repr(result)


def test_witness_redirect_is_derived_without_following():
    scope = validate_scope('http://example.com/?next=x', [])
    sock = FakeSocket(b'HTTP/1.1 302 Found\r\nLocation: https://example.invalid/\r\nContent-Length: 0\r\n\r\n')
    resolver = Mock(return_value=[answer()])
    transport = SafeTransport(scope, resolver=resolver, socket_factory=Mock(return_value=sock),
                              approved_probes={'http://example.com/?next=x': ['next']})
    result = transport.observe_probe('http://example.com/?next=x', 'next', 'witness')
    assert result['witness_match'] is True
    assert b'next=https%3A%2F%2Fexample.invalid%2F' in sock.sent[0]
    assert resolver.call_count == 1 and len(sock.sent) == 1
    assert 'example.invalid' not in repr(result)


def test_malformed_cookie_attributes_are_indeterminate():
    payload = (b'HTTP/1.1 200 OK\r\nSet-Cookie: private-name=private-value; SameSite=bogus\r\n'
               b'Content-Length: 0\r\n\r\n')
    transport, _, _, _ = build(payload)
    result = transport.observe('GET', URL)
    assert result['cookies']['indeterminate'] == 1
    assert 'private' not in repr(result)


def test_malformed_cookie_name_is_indeterminate():
    transport, _, _, _ = build(b'HTTP/1.1 200 OK\r\nSet-Cookie: bad name=private; Secure; HttpOnly; SameSite=Lax\r\nContent-Length: 0\r\n\r\n')
    assert transport.observe('GET', URL)['cookies']['indeterminate'] == 1


def test_observe_never_exposes_unexpected_exception():
    import traceback
    transport, _, resolver, _ = build()
    resolver.side_effect = RuntimeError('exception-secret')
    result = transport.observe('GET', URL)
    assert result == {'outcome': 'error'}
    assert 'exception-secret' not in repr(result) + traceback.format_exc()
    assert transport.blocked


def test_invalid_host_traceback_is_sanitized():
    import traceback
    sentinel = 'host' + '_secret'
    url = 'http://' + sentinel + '/'
    try:
        validate_scope(url, [])
    except TransportError:
        rendered = traceback.format_exc()
    else:
        pytest.fail('must reject invalid hostname')
    assert sentinel not in rendered


def test_scope_error_traceback_excludes_authority_secret():
    import traceback
    sentinel = 'authority' + '-secret'
    url = 'http://example.com:' + sentinel + '/'
    try:
        validate_scope(url, [])
    except TransportError:
        rendered = traceback.format_exc()
    else:
        pytest.fail('must reject invalid port')
    assert sentinel not in rendered


def test_internal_request_sanitizes_unexpected_exception_traceback():
    import traceback
    transport, _, resolver, _ = build()
    resolver.side_effect = RuntimeError('unexpected-source-secret')
    try:
        transport.request('GET', URL)
    except TransportError:
        rendered = traceback.format_exc()
    else:
        pytest.fail('must fail closed')
    assert 'unexpected-source-secret' not in rendered
    assert transport.blocked


def test_probe_duplicate_key_and_unapproved_route_never_resolve():
    url = 'http://example.com/?q=a&q=b'
    resolver = Mock(return_value=[answer()])
    transport = SafeTransport(validate_scope(url, []), resolver=resolver, socket_factory=Mock(),
                              approved_probes={url: ['q']})
    assert transport.observe_probe(url, 'q', 'reflection') == {'outcome': 'error'}
    assert transport.observe_probe('http://example.com/?q=other', 'q', 'reflection') == {'outcome': 'error'}
    resolver.assert_not_called()


def test_truncated_response_does_not_succeed_or_emit_probe_negative():
    url = 'http://example.com/?q=x'
    sock = FakeSocket(b'HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial')
    transport = SafeTransport(validate_scope(url, []), resolver=Mock(return_value=[answer()]), socket_factory=Mock(return_value=sock), approved_probes={url: ['q']})
    result = transport.observe_probe(url, 'q', 'reflection')
    assert result['outcome'] in ('error', 'indeterminate')
    assert 'reflected' not in result
    assert transport.blocked


def test_concurrent_failure_latches_before_queued_probe():
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    url = 'http://example.com/?q=x'
    entered, release = Event(), Event()
    def failing_dns(*args, **kwargs):
        entered.set()
        assert release.wait(3)
        raise RuntimeError('private-sentinel')
    resolver = Mock(side_effect=failing_dns)
    factory = Mock()
    transport = SafeTransport(validate_scope(url, []), resolver=resolver, socket_factory=factory, approved_probes={url: ['q']})
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(transport.observe, 'GET', url)
        assert entered.wait(3)
        second = pool.submit(transport.observe_probe, url, 'q', 'reflection')
        release.set()
        results = [first.result(timeout=3), second.result(timeout=3)]
    assert all(r['outcome'] == 'error' for r in results)
    assert 'private-sentinel' not in repr(results)
    assert transport.blocked and resolver.call_count == 1
    factory.assert_not_called()


def test_approval_cannot_add_absent_query_parameter():
    url = 'http://example.com/?q=x'
    resolver = Mock(return_value=[answer()])
    with pytest.raises(TransportError):
        SafeTransport(validate_scope(url, []), resolver=resolver, socket_factory=Mock(), approved_probes={url: ['other']})
    resolver.assert_not_called()


@pytest.mark.parametrize('body,matched', [(b'FORTRESSINERT2026', True), (b'no marker', False)])
def test_single_probe_is_uncorroborated_observation(body, matched):
    url = 'http://example.com/?q=x'
    payload = b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body
    sock = FakeSocket(payload)
    transport = SafeTransport(validate_scope(url, []), resolver=Mock(return_value=[answer()]), socket_factory=Mock(return_value=sock), approved_probes={url: ['q']})
    result = transport.observe_probe(url, 'q', 'reflection')
    assert result['outcome'] == 'indeterminate'
    assert result['reflected'] is matched
    assert result['evidence'] == 'single_raw_observation_not_confirmation'


@pytest.mark.parametrize('cookie', [b'a=x, b=y; Secure; HttpOnly; SameSite=Lax', b'a=x; Secure; Secure=false; HttpOnly; SameSite=Lax', b'a=x; HttpOnly; HttpOnly; Secure; SameSite=Lax'])
def test_ambiguous_cookies_are_indeterminate(cookie):
    transport, _, _, _ = build(b'HTTP/1.1 200 OK\r\nSet-Cookie: ' + cookie + b'\r\nContent-Length: 0\r\n\r\n')
    facts = transport.observe('GET', URL)['cookies']
    assert facts['indeterminate'] == 1


@pytest.mark.parametrize('url', ['http://example.com/safe/..;/admin', 'http://example.com/?q=x&Q=y', 'http://example.com/?q=x%26Q=y'])
def test_ambiguous_routes_refused_before_network(url):
    with pytest.raises(TransportError):
        validate_scope(url, [])


def test_late_split_challenge_halts_without_reading_rest(monkeypatch):
    import http.client
    original = http.client.HTTPResponse.read1
    calls = []
    def small_reads(self, amount):
        calls.append(1)
        return original(self, min(amount, 8194))
    monkeypatch.setattr(http.client.HTTPResponse, 'read1', small_reads)
    body = b'x' * 8192 + b'captcha' + b'y' * 50000
    transport, _, resolver, _ = build(b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)
    assert transport.observe('GET', URL)['outcome'] == 'blocked'
    assert len(calls) == 2
    transport.observe('GET', URL)
    assert resolver.call_count == 1


@pytest.mark.parametrize('status,header,expected', [(503, 'Retry-After: 60\r\n', 'blocked'), (500, '', 'indeterminate'), (404, '', 'indeterminate'), (304, '', 'indeterminate')])
def test_error_status_observations_are_not_success(status, header, expected):
    payload = f'HTTP/1.1 {status} Result\r\n{header}Content-Length: 0\r\n\r\n'.encode()
    transport, _, resolver, _ = build(payload)
    assert transport.observe('GET', URL)['outcome'] == expected
    assert transport.blocked
    transport.observe('GET', URL)
    assert resolver.call_count == 1


@pytest.mark.parametrize('header', ['rEtRy-AfTeR: 60', 'cF-MiTiGaTeD: challenge', 'x-SuCuRi-BlOcK: yes'])
def test_known_signals_on_success_halt_before_followup(header):
    payload = f'HTTP/1.1 200 OK\r\n{header}\r\nContent-Length: 2\r\n\r\nOK'.encode()
    transport, _, resolver, _ = build(payload)
    assert transport.observe('GET', URL)['outcome'] == 'blocked'
    transport.observe('GET', URL)
    assert resolver.call_count == 1


def test_case_colliding_request_headers_rejected_before_dns():
    transport, _, resolver, _ = build()
    with pytest.raises(TransportError):
        transport.request('GET', URL, {'Origin': 'x', 'origin': 'y'})
    resolver.assert_not_called()


def test_query_parser_normalization_collision_rejected():
    with pytest.raises(TransportError):
        validate_scope('http://example.com/?a.b=x&a_b=y', [])


def test_partial_representation_is_indeterminate_and_halts():
    transport, _, resolver, _ = build(b'HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-1/100\r\nContent-Length: 2\r\n\r\nOK')
    assert transport.observe('GET', URL)['outcome'] == 'indeterminate'
    assert transport.blocked
    transport.observe('GET', URL)
    assert resolver.call_count == 1


def test_scoped_probe_is_kind_bound_and_forges_inert_query():
    resolver = Mock(return_value=[answer()])
    sock = FakeSocket(b'HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\nFORTRESSINERT2026')
    transport = SafeTransport(validate_scope(URL, []), resolver=resolver, socket_factory=Mock(return_value=sock),
                              scoped_probes={(URL, 'q', 'reflection')})
    assert transport.observe_scoped_probe(URL, 'q', 'witness') == {'outcome': 'error'}
    assert resolver.call_count == 0
    # Rejected input halts this audit; valid input needs a fresh instance.
    assert transport.observe_scoped_probe(URL, 'q', 'reflection') == {'outcome': 'error'}
    transport = SafeTransport(validate_scope(URL, []), resolver=resolver, socket_factory=Mock(return_value=sock), scoped_probes={(URL, 'q', 'reflection')})
    result = transport.observe_scoped_probe(URL, 'q', 'reflection')
    assert result['reflected'] is True and result['outcome'] == 'indeterminate'
    assert sock.sent[0].startswith(b'GET /?q=FORTRESSINERT2026 HTTP/1.1\r\n')
    assert resolver.call_count == 1


def test_scoped_witness_fixed_choices_no_fetch_and_no_confirmation():
    resolver = Mock(return_value=[answer()])
    sock = FakeSocket(b'HTTP/1.1 302 Found\r\nLocation: https://second.invalid/\r\nContent-Length: 0\r\n\r\n')
    transport = SafeTransport(validate_scope(URL, []), resolver=resolver, socket_factory=Mock(return_value=sock),
                              scoped_probes={(URL, 'next', 'witness')})
    assert transport.observe_scoped_probe(URL, 'next', 'witness', witness='https://evil.invalid/') == {'outcome': 'error'}
    assert resolver.call_count == 0
    assert transport.observe_scoped_probe(URL, 'next', 'witness', witness='second') == {'outcome': 'error'}
    transport = SafeTransport(validate_scope(URL, []), resolver=resolver, socket_factory=Mock(return_value=sock), scoped_probes={(URL, 'next', 'witness')})
    result = transport.observe_scoped_probe(URL, 'next', 'witness', witness='second')
    assert result['outcome'] == 'indeterminate' and result['witness_match'] is True
    assert b'GET /?next=https%3A%2F%2Fsecond.invalid%2F HTTP/1.1' in sock.sent[0]
    assert resolver.call_count == 1 and resolver.call_args.args[0] == 'example.com'
    assert 'invalid' not in repr(result)


@pytest.mark.parametrize('acao,expected', [('https://fortress-origin.invalid', 'match'), ('*', 'wildcard'), ('private-secret', 'other'), (None, 'absent')])
def test_fixed_cors_returns_only_enums_and_never_follows(acao, expected):
    header = b'' if acao is None else ('Access-Control-Allow-Origin: ' + acao + '\r\n').encode()
    sock = FakeSocket(b'HTTP/1.1 200 OK\r\n' + header + b'Access-Control-Allow-Credentials: true\r\nSet-Cookie: secret=secret\r\nX-Secret: secret\r\nContent-Length: 6\r\n\r\nsecret')
    resolver = Mock(return_value=[answer()])
    transport = SafeTransport(validate_scope(URL, []), resolver=resolver, socket_factory=Mock(return_value=sock), cors_routes={URL})
    assert transport.observe_cors('POST', URL) == {'outcome': 'error'}
    # Verify the query rejection independently, not merely the halt latch.
    rejected_query = SafeTransport(validate_scope(URL, []), resolver=resolver, socket_factory=Mock(return_value=sock), cors_routes={URL})
    assert rejected_query.observe_cors('GET', URL + '?x=y') == {'outcome': 'error'}
    assert rejected_query.blocked
    assert resolver.call_count == 0
    # Fail closed on validation errors; a new instance tests normal CORS.
    assert transport.observe_cors('OPTIONS', URL) == {'outcome': 'error'}
    transport = SafeTransport(validate_scope(URL, []), resolver=resolver, socket_factory=Mock(return_value=sock), cors_routes={URL})
    result = transport.observe_cors('OPTIONS', URL)
    assert result == {'outcome': 'ok', 'status': 200, 'acao': expected, 'acac': True}
    assert b'origin: https://fortress-origin.invalid\r\n' in sock.sent[0]
    assert resolver.call_count == 1 and resolver.call_args.args[0] == 'example.com'
    assert 'secret' not in repr(result)


@pytest.mark.parametrize('approval', [
    ('http://example.com/?q=x', 'q', 'reflection'), (URL, 'password', 'reflection'),
    (URL, 'q', 'unknown'), ('http://other.example/', 'q', 'reflection'),
    (URL, 'x&z', 'reflection'),
])
def test_invalid_scoped_approvals_refused_before_dns(approval):
    resolver = Mock(return_value=[answer()])
    with pytest.raises(TransportError):
        SafeTransport(validate_scope(URL, []), resolver=resolver, scoped_probes=[approval])
    resolver.assert_not_called()


@pytest.mark.parametrize('status,header,outcome', [(401, '', 'blocked'), (403, '', 'blocked'), (429, '', 'blocked'), (200, 'CF-Mitigated: challenge\r\n', 'blocked'), (206, '', 'indeterminate')])
@pytest.mark.parametrize('mode', ['probe', 'cors'])
def test_deep_block_and_partial_halt_before_body_and_followup(status, header, outcome, mode, monkeypatch):
    import http.client
    def forbidden(*args, **kwargs):
        raise AssertionError('unexpected body read')
    monkeypatch.setattr(http.client.HTTPResponse, 'read1', forbidden)
    sock = FakeSocket(f'HTTP/1.1 {status} Result\r\n{header}Content-Length: 99999\r\n\r\n'.encode())
    resolver = Mock(return_value=[answer()])
    transport = SafeTransport(validate_scope(URL, []), resolver=resolver, socket_factory=Mock(return_value=sock), scoped_probes={(URL, 'q', 'reflection')}, cors_routes={URL})
    run = (lambda: transport.observe_scoped_probe(URL, 'q', 'reflection')) if mode == 'probe' else (lambda: transport.observe_cors('GET', URL))
    assert run() == {'outcome': outcome}
    assert transport.blocked
    assert run() == {'outcome': 'error'}
    assert resolver.call_count == 1


def test_concurrent_deep_requests_share_budget_and_lock():
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    entered, release = Event(), Event()
    def delayed_resolver(*args, **kwargs):
        entered.set()
        assert release.wait(3)
        return [answer()]
    resolver = Mock(side_effect=delayed_resolver)
    sock = FakeSocket()
    transport = SafeTransport(validate_scope(URL, []), resolver=resolver, socket_factory=Mock(return_value=sock), scoped_probes={(URL, 'q', 'reflection')}, cors_routes={URL}, max_requests=1)
    with ThreadPoolExecutor(max_workers=2) as pool:
        one = pool.submit(transport.observe_cors, 'GET', URL)
        assert entered.wait(3)
        two = pool.submit(transport.observe_scoped_probe, URL, 'q', 'reflection')
        release.set()
        results = [one.result(timeout=3), two.result(timeout=3)]
    assert results[0]['outcome'] == 'ok' and results[1]['outcome'] == 'error'
    assert transport.count == resolver.call_count == len(sock.sent) == 1


@pytest.mark.parametrize('mode', ['probe', 'cors'])
def test_deep_redirect_never_follows_even_scoped(mode):
    sock = FakeSocket(b'HTTP/1.1 302 Found\r\nLocation: /two\r\nContent-Length: 0\r\n\r\n')
    resolver = Mock(return_value=[answer()])
    transport = SafeTransport(validate_scope(URL, ['http://example.com/two']), resolver=resolver, socket_factory=Mock(return_value=sock), scoped_probes={(URL, 'q', 'reflection')}, cors_routes={URL})
    result = transport.observe_scoped_probe(URL, 'q', 'reflection') if mode == 'probe' else transport.observe_cors('GET', URL)
    assert result['outcome'] != 'ok' and resolver.call_count == len(sock.sent) == 1


def test_deadline_expired_before_dns():
    transport, sock, resolver, factory = build()
    transport.started -= 100
    with pytest.raises(TransportError): transport.request('GET', URL)
    resolver.assert_not_called()


def test_scoped_baseline_derived_flags_and_status_without_raw_data():
    body = b"FORTRESSINERT2026 private-body"
    payload = b"HTTP/1.1 200 OK\r\nX-Secret: private-header\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    transport, sock, resolver, _ = build(payload, scoped_probes={(URL, "q", "reflection")})
    assert transport.observe_scoped_baseline(URL, "other", "reflection") == {"outcome": "error"}
    resolver.assert_not_called()
    assert transport.observe_scoped_baseline(URL, "q", "reflection") == {"outcome": "error"}
    transport, sock, resolver, _ = build(payload, scoped_probes={(URL, "q", "reflection")})
    result = transport.observe_scoped_baseline(URL, "q", "reflection")
    # False means no literal match, not absence of an encoded signal.
    assert result == {"outcome": "ok", "status": 200, "literal_marker_observed": True, "literal_first_witness_observed": False, "literal_second_witness_observed": False}
    assert "private" not in repr(result) and "example" not in repr(result)
    assert sock.sent[0].startswith(b"GET / HTTP/1.1")


def test_cors_includes_observed_success_status():
    transport, _, _, _ = build(cors_routes={URL})
    assert transport.observe_cors('GET', URL)['status'] == 200


def test_scoped_approval_normalized_collision_is_rejected_before_dns():
    resolver = Mock(return_value=[answer()])
    with pytest.raises(TransportError):
        SafeTransport(validate_scope(URL, []), resolver=resolver,
                      scoped_probes=[(URL, 'a.b', 'reflection'), (URL, 'a_b', 'witness')])
    resolver.assert_not_called()
