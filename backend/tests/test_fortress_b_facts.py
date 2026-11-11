import json
import pytest
from app import fortress_advanced_core as core


@pytest.mark.parametrize('status,extra', [(200,b''),(204,b''),(304,b'Content-Length: 12\r\n'),(403,b'Transfer-Encoding: gzip, chunked\r\n')])
def test_complete_statuses_and_framing(status, extra):
    facts = core.analyze_head_facts(b'HTTP/1.1 '+str(status).encode()+b' X\r\n'+extra+b'\r\n')
    assert core.validate_head_facts(facts)
    assert facts['observations']['http_status'] == status


@pytest.mark.parametrize('raw', [b'HTTP/1.1 200 OK\r\nX: PRIVATE', b'HTTP/1.1 204 OK\r\nContent-Length: 0\r\n\r\n', b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 1\r\n\r\n', b'HTTP/1.1 200 OK\r\nX: '+b'a'*32768+b'\r\n\r\n'], ids=['incomplete', '204-length', 'ambiguous', 'oversize'])
def test_incomplete_or_ambiguous_facts_fail_closed(raw):
    assert core.analyze_head_facts(raw) is None


@pytest.mark.parametrize('field', ['csp_effective', 'csp_report_only_effective'])
def test_csp_same_directive_conflicting_modes_rejected(field):
    facts = core.analyze_head_facts(
        b"HTTP/1.1 200 OK\r\nContent-Security-Policy: script-src 'unsafe-inline'\r\n"
        b"Content-Security-Policy-Report-Only: script-src 'unsafe-inline'\r\n\r\n"
    )
    assert core.validate_head_facts(facts)
    observations = facts['observations']
    observations[field][1]['mode'] = 'uncertain'
    facts['findings'] = core.findings(observations)
    for finding in facts['findings']:
        finding['route_id'] = 'head-route-1'
    assert not core.validate_head_facts(facts)


def test_csp_same_directive_different_modes_in_distinct_policies_accepted():
    facts = core.analyze_head_facts(
        b"HTTP/1.1 200 OK\r\nContent-Security-Policy: script-src 'unsafe-inline'\r\n"
        b"Content-Security-Policy-Report-Only: script-src 'unsafe-inline' 'nonce-synthetic'\r\n\r\n"
    )
    observations = facts['observations']
    assert {item['mode'] for item in observations['csp_effective']} == {'review'}
    assert {item['mode'] for item in observations['csp_report_only_effective']} == {'uncertain'}
    assert core.validate_head_facts(facts)
    assert 'nonce-synthetic' not in json.dumps(facts)


def test_internal_analysis_exception_does_not_escape(monkeypatch):
    def fail(*_): raise ValueError('FAKE_SECRET')
    monkeypatch.setattr(core, 'hsts', fail)
    result = core.analyze_head_facts(b'HTTP/1.1 200 OK\r\nX: FAKE_SECRET\r\n\r\n')
    assert result is None
    assert 'FAKE_SECRET' not in json.dumps(result)
