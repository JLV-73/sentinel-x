import json
import copy
import pytest
from app.fortress_advanced import analyze_fixture, validate_report


def test_csp_known_directives_project_inline_without_values_and_report_only():
    r = analyze_fixture(b"HTTP/1.1 200 OK\r\nContent-Security-Policy: script-src 'unsafe-inline' 'nonce-CANARYsecret'; custom-canary CANARYsecret\r\nContent-Security-Policy-Report-Only: style-src 'unsafe-inline' https://CANARYsecret.invalid\r\n\r\n")
    assert r['observations']['csp_directives'] == [{'directive': 'script-src', 'unsafe_inline': True}]
    assert r['observations']['csp_report_only_directives'] == [{'directive': 'style-src', 'unsafe_inline': True}]
    assert {f['rule_id'] for f in r['findings']} >= {'csp.active_inline.v1', 'csp.report_only_inline.v1'}
    assert 'CANARYsecret' not in json.dumps(r)
    assert validate_report(r)


def test_cookie_prefix_and_missing_properties_are_contextual_and_redacted(caplog, capsys):
    r = analyze_fixture(b'HTTP/1.1 200 OK\r\nSet-Cookie: __Host-CANARYname=CANARYvalue; Domain=CANARYdomain; Path=/; Secure\r\nSet-Cookie: __Secure-CANARYother=CANARYvalue; HttpOnly\r\n\r\n')
    assert r['observations']['cookie_prefix'] == {'state': 'observed', 'violations': 2}
    assert {f['rule_id'] for f in r['findings']} >= {'cookie.prefix_requirements.v1', 'cookie.missing_secure.v1', 'cookie.missing_httponly.v1'}
    assert all(f['priority'] == 'unclassified' and f['route_id'] == r['scope']['route_id'] for f in r['findings'])
    assert 'CANARY' not in json.dumps(r) + caplog.text + str(capsys.readouterr())
    assert validate_report(r)


def test_untrusted_provenance_declarations_are_separate_and_never_attest_tls():
    from app.fortress_advanced import validate_declaration
    for kind in ('live', 'imported', 'fixture'):
        declaration = {'schema_version': 'fortress.declaration/1', 'provenance': {'declared_kind': kind, 'attestation': 'none'},
                       'execution': {'declared_state': 'incomplete', 'request_sent': 'unknown'}, 'scope': {'route_id': 'fixture-route-1', 'method': 'HEAD'}}
        assert validate_declaration(declaration)
        assert not validate_report(declaration)
        declaration['provenance']['tls'] = 'verified'
        assert not validate_declaration(declaration)
    fixture = analyze_fixture(b'HTTP/1.1 200 OK\r\n\r\n')
    fixture['provenance']['kind'] = 'live'
    assert not validate_report(fixture)


@pytest.mark.parametrize('header', [
    b"Content-Security-Policy: script-src 'unsafe-inline'\r\nContent-Security-Policy: default-src 'none'\r\n",
    b"Content-Security-Policy: script-src 'unsafe-inline', default-src 'none'\r\n",
    b"Content-Security-Policy: script-src 'unsafe-inline'; script-src 'none'\r\n",
])
def test_ambiguous_csp_does_not_project_directives(header):
    r = analyze_fixture(b'HTTP/1.1 200 OK\r\n' + header + b'\r\n')
    assert r['observations']['csp'] == 'indeterminate'
    assert r['observations']['csp_directives'] == []
    assert not any(f['rule_id'] == 'csp.active_inline.v1' for f in r['findings'])
    assert validate_report(r)


@pytest.mark.parametrize('cookie,violations', [
    (b'__Host-x=y; Secure; Path=/', 0),
    (b'__Host-x=y; Secure', 1),
    (b'__Host-x=y; Secure; Path=/sub', 1),
    (b'__Secure-x=y; Secure', 0),
    (b'__Secure-x=y', 1),
    (b'__host-x=y', 0),
])
def test_cookie_prefix_bounded_rules(cookie, violations):
    r = analyze_fixture(b'HTTP/1.1 200 OK\r\nSet-Cookie: ' + cookie + b'\r\n\r\n')
    assert r['observations']['cookie_prefix']['violations'] == violations
    assert validate_report(r)


def test_incomplete_never_infers_absence_and_rejects_forged_projection():
    r = analyze_fixture(b'HTTP/1.1 200 OK\r\nSet-Cookie: x=y\r\n')
    assert r['observations']['cookie_prefix']['state'] == 'not_evaluated'
    assert not r['findings'] and validate_report(r)
    completed = analyze_fixture(b'HTTP/1.1 200 OK\r\n\r\n')
    for edit in ('unknown_directive', 'route', 'prefix'):
        forged = copy.deepcopy(completed)
        if edit == 'unknown_directive': forged['observations']['csp_directives'] = [{'directive': 'CANARY', 'unsafe_inline': True}]
        if edit == 'route': forged['findings'][0]['route_id'] = 'CANARY'
        if edit == 'prefix': forged['observations']['cookie_prefix']['violations'] = 0
        assert not validate_report(forged)
