import json
import pytest


@pytest.mark.parametrize('data', [b'HTTP/1.1 200 OK\r\nX: y\r\n', b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n', b'HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n'])
def test_bad_framing_is_incomplete_without_http_or_absence(data):
    from app.fortress_advanced import analyze_fixture
    r = analyze_fixture(data)
    assert r['execution']['state'] == 'incomplete'
    assert r['observations']['http_status'] is None
    assert r['observations']['hsts'] == 'not_evaluated'
    assert not r['findings']


@pytest.mark.parametrize('head', [b'HTTP/1.1 204 No Content\r\n\r\n', b'HTTP/1.1 304 Not Modified\r\nContent-Length: 10\r\n\r\n', b'HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n'])
def test_valid_head_framing(head):
    from app.fortress_advanced import analyze_fixture
    assert analyze_fixture(head)['execution']['state'] == 'completed'


def test_sensitive_values_never_project_and_analyzers_are_contextual(caplog):
    from app.fortress_advanced import analyze_fixture
    head = (b'HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=0\r\n'
            b"Content-Security-Policy: img-src 'unsafe-inline'; script-src 'self'\r\n"
            b"Content-Security-Policy-Report-Only: script-src 'unsafe-inline' https://secret-marker.invalid\r\n"
            b'Set-Cookie: name-marker=value-marker; Secure; HttpOnly; SameSite=Lax\r\n\r\n')
    r = analyze_fixture(head)
    assert r['observations']['hsts'] == 'disabled'
    assert r['observations']['csp'] == 'present'
    assert r['observations']['csp_report_only'] == 'present'
    assert r['observations']['cookies'] == {'state': 'observed', 'count': 1, 'secure': 1, 'httponly': 1, 'samesite': 1}
    assert not any(f['rule_id'] == 'csp.active_inline.v1' for f in r['findings'])
    assert all(x not in json.dumps(r) + caplog.text for x in ('name-marker', 'value-marker', 'secret-marker'))


def test_duplicate_ambiguous_values_are_not_compliant():
    from app.fortress_advanced import analyze_fixture
    r = analyze_fixture(b'HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=0\r\nStrict-Transport-Security: max-age=10\r\nSet-Cookie: x=y; Secure; Secure\r\n\r\n')
    assert r['observations']['hsts'] == 'indeterminate'
    assert r['observations']['cookies']['state'] == 'indeterminate'


def test_contract_is_closed_and_cannot_promote_fixture_to_live():
    from app.fortress_advanced import analyze_fixture, validate_report
    r = analyze_fixture(b'HTTP/1.1 200 OK\r\n\r\n')
    assert validate_report(r) is True
    r['provenance']['kind'] = 'live'
    assert validate_report(r) is False
    r['provenance']['kind'] = 'fixture'
    r['findings'][0]['priority'] = 'investigate'
    assert validate_report(r) is False
