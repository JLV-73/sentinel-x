import json
import traceback
import pytest
from app.fortress_advanced import analyze_fixture, validate_report
from app import fortress_advanced_core as core


def head(header):
    return b'HTTP/1.1 200 OK\r\n' + header + b'\r\n'


def test_csp_fallback_overridden_no_inline_advice():
    r = analyze_fixture(head(b"Content-Security-Policy: default-src 'unsafe-inline'; script-src 'none'; style-src 'none'\r\n"))
    assert not any(f['recommendation'] == 'review_inline_in_context' for f in r['findings'])
    assert validate_report(r)


def test_csp_specific_fallback_report_only_and_nonce():
    r = analyze_fixture(head(b"Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; script-src-elem 'none'; style-src 'unsafe-inline' 'nonce-SECRET'\r\nContent-Security-Policy-Report-Only: style-src 'unsafe-inline'\r\n"))
    fs = [f for f in r['findings'] if f['recommendation'] == 'review_inline_in_context']
    assert any(f['rule_id'] == 'csp.active_inline.v1' and f['evidence'] == 'script-src' for f in fs)
    assert not any(f['rule_id'] == 'csp.active_inline.v1' and f['evidence'] == 'style-src' for f in fs)
    assert any(f['rule_id'] == 'csp.report_only_inline.v1' for f in fs)
    assert 'SECRET' not in json.dumps(r)
    assert validate_report(r)


def test_cookie_all_attributes_checked():
    r = analyze_fixture(head(b'Set-Cookie: __Host-x=y; Secure; Path=/; Foo=\xff\r\n'))
    assert r['observations']['cookies']['state'] == 'indeterminate'
    assert r['observations']['cookie_prefix']['violations'] is None
    assert validate_report(r)


def test_helper_fault_does_not_escape_with_traceback_locals(monkeypatch, caplog):
    marker = 'FAKE_INTERNAL_SECRET_7C0'
    def broken(_):
        secret = marker
        raise RuntimeError(secret)
    monkeypatch.setattr(core, 'cookies', broken)
    try:
        r = analyze_fixture(head(b'Set-Cookie: x=y\r\n'))
    except Exception as exc:
        trace = ''.join(traceback.TracebackException.from_exception(exc, capture_locals=True).format(chain=True))
        pytest.fail('exception escaped; marker exposed: ' + str(marker in trace), pytrace=False)
    assert r['execution']['state'] == 'failed'
    assert r['execution']['cause'] == 'internal_error_unknown'
    assert not r['findings'] and r['observations'] == core.empty()
    assert marker not in json.dumps(r) + caplog.text
    assert validate_report(r)


def test_qualification_closed_domain():
    r = analyze_fixture(head(b'Set-Cookie: x=y\r\n'))
    assert {f['qualification'] for f in r['findings']} <= {'confirmed', 'investigate', 'not_evaluated'}
    assert validate_report(r)


@pytest.mark.parametrize('kind,suffix', [('script', 'elem'), ('script', 'attr'), ('style', 'elem'), ('style', 'attr')])
def test_csp_each_sink_uses_specific_directive_before_parent_and_default(kind, suffix):
    policy = f"default-src 'unsafe-inline'; {kind}-src 'none'; {kind}-src-{suffix} 'unsafe-inline'"
    r = analyze_fixture(head(b'Content-Security-Policy: ' + policy.encode() + b'\r\n'))
    e = r['observations']['csp_effective']
    assert {'sink': kind + '-' + suffix, 'directive': kind + '-src-' + suffix, 'mode': 'review'} in e
    other = 'attr' if suffix == 'elem' else 'elem'
    assert not any(x['sink'] == kind + '-' + other for x in e)
    assert validate_report(r)


@pytest.mark.parametrize('source', ["'nonce-fake'", "'sha256-fake'"])
def test_csp_nonce_and_hash_are_not_inline_advice(source):
    policy = "script-src 'unsafe-inline' " + source
    r = analyze_fixture(head(b'Content-Security-Policy: ' + policy.encode() + b'\r\n'))
    assert all(f['recommendation'] != 'review_inline_in_context' for f in r['findings'])
    assert validate_report(r)


@pytest.mark.parametrize('helper', ['csp', 'csp_projection', 'csp_effective', 'cookies', 'cookie_prefix', 'findings', 'empty'])
def test_helper_exceptions_closed_without_escaping_traceback(monkeypatch, helper):
    def broken(*args):
        secret = 'INJECTED_TRACE_SECRET'
        raise RuntimeError(secret)
    monkeypatch.setattr(core, helper, broken)
    try:
        result = analyze_fixture(head(b'Set-Cookie: x=y\r\n'))
    except Exception as exc:
        rendered = ''.join(traceback.TracebackException.from_exception(exc, capture_locals=True).format(chain=True))
        pytest.fail('helper exception escaped; secret in traceback: ' + str('INJECTED_TRACE_SECRET' in rendered), pytrace=False)
    assert result['execution']['cause'] == 'internal_error_unknown'
    assert 'INJECTED_TRACE_SECRET' not in json.dumps(result)
