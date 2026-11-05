"""Acceptance checks for the owned-loopback strict standard lab."""
import json
import sys
from datetime import date
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import fortress_standard_lab_server as lab


@pytest.mark.parametrize('scenario,status', [('positive', 200), ('negative', 200), ('indeterminate', 403)])
def test_real_fixture_status_and_redaction(scenario, status):
    result = lab.run_scenario(scenario)
    assert result['http_status'] == status
    assert result['requests_used'] == 1
    assert result['scope'] == {'origin': '[redacted]', 'paths': ['[redacted route]']}
    assert all(date.fromisoformat(f['date']) for f in result['findings'])
    assert 'lab-secret' not in json.dumps(result)
    if scenario == 'indeterminate':
        assert all(f['status'] == 'indeterminate' for f in result['findings'])


def test_fixture_evidence_changes_with_response(monkeypatch):
    baseline = lab.run_scenario('positive')
    original = lab._fixture_response
    def modified(scenario):
        return original(scenario).replace(b'; Secure', b'')
    monkeypatch.setattr(lab, '_fixture_response', modified)
    changed = lab.run_scenario('positive')
    def cookie(result):
        return next(f for f in result['findings'] if f['id'] == 'cookie_attributes')
    assert cookie(baseline)['evidence_code'] == 'cookie_attributes_present'
    assert cookie(changed)['evidence_code'] == 'cookie_attributes_missing'


@pytest.mark.parametrize('response,status,state', [
    (b'HTTP/1.1 302 Found\r\nLocation: https://private.invalid/canary-location\r\nContent-Length: 0\r\n\r\n', 302, 'redirected'),
    (b'HTTP/1.1 200 OK\r\nSet-Cookie: a=canary-cookie\r\n', None, 'blocked'),
])
def test_redirect_or_incomplete_never_invents_evidence(monkeypatch, response, status, state):
    monkeypatch.setattr(lab, '_fixture_response', lambda _: response)
    result = lab.run_scenario('positive')
    assert result['http_status'] == status
    assert result['route_execution'][0]['state'] == state
    assert all(f['status'] == 'indeterminate' for f in result['findings'])
    assert 'canary-' not in json.dumps(result)
