import json
import socket
import threading
import pytest
from owned_lab_helpers import make_transport
from test_fortress_transport import URL, build
from app.fortress_standard_facts import header_value_facts


@pytest.mark.parametrize('headers,complete,expected', [
    ([], True, {'hsts': 'absent', 'csp': 'absent'}),
    ([('Strict-Transport-Security', 'max-age=0')], True, {'hsts': 'zero_max_age', 'csp': 'absent'}),
    ([('Strict-Transport-Security', 'max-age=12345678901')], True, {'hsts': 'unknown', 'csp': 'absent'}),
    ([('Strict-Transport-Security', 'max-age=1; max-age=2')], True, {'hsts': 'unknown', 'csp': 'absent'}),
    ([('Strict-Transport-Security', 'max-age=1'), ('strict-transport-security', 'max-age=1')], True, {'hsts': 'unknown', 'csp': 'absent'}),
    ([('Content-Security-Policy', "default-src 'none'; script-src https://secret.invalid")], True, {'hsts': 'absent', 'csp': 'unknown'}),
    ([('Content-Security-Policy', 'a' * 4097)], True, {'hsts': 'absent', 'csp': 'unknown'}),
    ([('Content-Security-Policy', '')], True, {'hsts': 'absent', 'csp': 'empty'}),
    ([], False, {'hsts': 'unknown', 'csp': 'unknown'}),
    ([], 1, {'hsts': 'unknown', 'csp': 'unknown'}),
])
def test_finite_fail_closed_observations(headers, complete, expected):
    assert header_value_facts(headers, complete) == expected


def test_refusal_and_body_limit_do_not_derive_facts():
    for payload in (b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n',
                    b'HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nshort'):
        result = build(payload)[0].observe_standard_facts('GET', URL)
        assert result['outcome'] != 'ok'
        assert set(result.get('header_value_facts', {}).values()) <= {'unknown'}


def test_body_over_budget_returns_no_facts():
    payload = (b'HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=1\r\n'
               b'Content-Length: 5\r\n\r\n12345')
    transport = build(payload, max_bytes=4)[0]
    assert transport.observe_standard_facts('GET', URL) == {'outcome': 'error'}
    assert transport.blocked


def test_owned_loopback_does_not_fetch_html_resources_or_expose_values(monkeypatch):
    class Lab: pass
    lab = Lab()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(('127.0.0.1', 0))
    listener.listen(2)
    listener.settimeout(2)
    lab.address = listener.getsockname()
    requests = []
    body = b'<script src="https://third-party-secret.invalid/a.js?token=private"></script>'
    payload = (b'HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=987654\r\n'
               b"Content-Security-Policy: default-src 'none'\r\nX-Private: header-secret\r\n"
               b'Content-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)
    def serve():
        conn, _ = listener.accept()
        with conn:
            requests.append(conn.recv(8192))
            conn.sendall(payload)
    thread = threading.Thread(target=serve)
    thread.start()
    try:
        monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **k: pytest.fail('unexpected DNS'))
        transport, urls, resolutions, adapters = make_transport(lab)
        result = transport.observe_standard_facts('GET', urls[0])
        thread.join(3)
        assert not thread.is_alive() and len(requests) == len(resolutions) == len(adapters) == 1
        assert adapters[0].actual_peer == lab.address
        assert result['header_value_facts'] == {'hsts': 'positive_max_age', 'csp': 'default_src_none'}
        assert all(s not in json.dumps(result) for s in ('987654', 'header-secret', 'third-party-secret', 'private'))
    finally:
        listener.close()
        thread.join(3)
