import copy
import json
import pytest
from app.fortress_advanced import analyze_fixture, validate_report


def test_incomplete_secret_bytes_produce_only_closed_codes(caplog, capsys):
    r = analyze_fixture(b'HTTP/1.1 200 OK\r\nX-Secret: FAKE_SECRET_TRACE_MARKER\r\n')
    assert validate_report(r)
    assert 'FAKE_SECRET_TRACE_MARKER' not in json.dumps(r) + caplog.text + str(capsys.readouterr())
    assert r['observations']['cookies']['count'] is None


@pytest.mark.parametrize('head', [
    b'HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n',
    b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\n',
    b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n',
    b'HTTP/1.1 200 OK\nX: x\n\n',
    b'HTTP/1.1 200 OK\r\n\r\nbody',
    b'HTTP/1.1 200 OK\r\nX: ' + b'a' * 32768 + b'\r\n\r\n',
], ids=['http10-te', 'bad-coding-order', 'duplicate-length', 'lf-only', 'body', 'oversized'])
def test_other_ambiguous_framings_not_evaluated(head):
    r = analyze_fixture(head)
    assert r['execution']['state'] == 'incomplete'
    assert validate_report(r)


def test_validator_rejects_route_state_and_observation_contradictions():
    r = analyze_fixture(b'HTTP/1.1 200 OK\r\n\r\n')
    variants = []
    for edit in ('route', 'state', 'finding', 'observation', 'unknown', 'imported'):
        v = copy.deepcopy(r)
        if edit == 'route': v['scope']['route_id'] = 'other'
        if edit == 'state': v['execution']['state'] = 'blocked'
        if edit == 'finding': v['findings'][0]['route_id'] = 'other'
        if edit == 'observation': v['observations']['hsts'] = 'positive'
        if edit == 'unknown': v['observations']['unexpected'] = 'marker'
        if edit == 'imported': v['provenance']['kind'] = 'imported'
        variants.append(v)
    assert all(not validate_report(v) for v in variants)


def test_cookie_empty_and_malformed_are_not_compliance():
    none = analyze_fixture(b'HTTP/1.1 200 OK\r\n\r\n')['observations']['cookies']
    broken = analyze_fixture(b'HTTP/1.1 200 OK\r\nSet-Cookie: malformed\r\n\r\n')['observations']['cookies']
    assert none['state'] == 'none_observed' and none['secure'] is None
    assert broken['state'] == 'indeterminate' and broken['secure'] is None
