"""Isolated qualification only: single-scope translation, contract and owned TLS lab."""
import importlib.util
import json
from pathlib import Path
import socket

import pytest
from fastapi.testclient import TestClient
from app import fortress_service, fortress_standard_contract
from app.fortress_single_scope import prepare_single_scope, SingleScopeError
from support_fortress_api import make_qualification_app

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('single_chain_lab', ROOT / 'scripts' / 'fortress_standard_lab_server.py')
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)
RAW = '{"url":"https://standard-lab.invalid/","authorized":true,"method":"GET"}'
HEADERS = {'Origin': 'http://test.local', 'X-Sentinel-Request': 'sync'}


def test_lab_prepares_trusted_single_scope(monkeypatch):
    calls = []
    real = prepare_single_scope
    def observe(raw):
        calls.append(raw)
        return real(raw)
    monkeypatch.setattr(lab, 'prepare_single_scope', observe, raising=False)
    report = lab.run_scenario('negative')
    assert calls == [RAW]
    assert report['requests_used'] == 1


def test_contract_qualification_uses_real_fixture(monkeypatch):
    """Test-only assembly: translation precedes contract; not the lab HTTP path."""
    connections = []
    original_connect = socket.socket.connect
    def connect(sock, address):
        assert address[0] == '127.0.0.1'
        connections.append(address)
        return original_connect(sock, address)
    def no_dns(*args, **kwargs):
        raise AssertionError('real DNS forbidden')
    monkeypatch.setattr(socket.socket, 'connect', connect)
    monkeypatch.setattr(socket, 'getaddrinfo', no_dns)
    fixture_connections = []
    original_fixture_connect = lab.FixtureSocket.connect
    def fixture_connect(sock, address):
        fixture_connections.append(address)
        return original_fixture_connect(sock, address)
    monkeypatch.setattr(lab.FixtureSocket, 'connect', fixture_connect)
    original_audit = fortress_service._audit_single_with_factory
    captured = []
    def capture(raw, **kwargs):
        result = original_audit(raw, **kwargs)
        captured.append((raw, result))
        return result
    monkeypatch.setattr(fortress_service, '_audit_single_with_factory', capture)
    # Exercise the real strict projector through the isolated legacy HTTP adapter.
    monkeypatch.setattr(fortress_standard_contract, '_project', fortress_standard_contract.project_strict)
    payload = prepare_single_scope(RAW)
    statuses = []
    for scenario in ('positive', 'negative', 'indeterminate'):
        def consumer(received):
            assert received == payload
            lab.run_scenario(scenario)
            observed_raw, result = captured.pop()
            assert observed_raw == RAW
            assert prepare_single_scope(observed_raw) == received
            return result
        with TestClient(make_qualification_app(consumer), base_url='http://test.local') as client:
            response = client.post('/api/fortress/audit', headers=HEADERS, json=payload)
        assert response.status_code == 200, response.text
        report = response.json()
        assert report['requests_used'] == 1 and report['complete'] is False
        assert 'lab-secret' not in response.text and lab.HOST not in response.text
        statuses.append(next(f['status'] for f in report['findings'] if f['id'] == 'cookie_attributes'))
    assert statuses == ['conformant', 'attention', 'indeterminate']
    assert fixture_connections == [(lab.FAKE_IP, 443)] * 3
    assert len(connections) >= 3  # Windows event-loop socketpairs also use loopback.


def test_fixture_response_mutation_changes_real_finding(monkeypatch):
    before = lab.run_scenario('negative')
    positive_bytes = lab._fixture_response('positive')
    monkeypatch.setattr(lab, '_fixture_response', lambda scenario: positive_bytes)
    after = lab.run_scenario('negative')
    def cookie(report):
        return next(f['status'] for f in report['findings'] if f['id'] == 'cookie_attributes')
    assert (cookie(before), cookie(after)) == ('attention', 'conformant')


@pytest.mark.parametrize('raw', [
    RAW.replace('true', 'false'), RAW.replace('"GET"', '"POST"'),
    RAW.replace('"authorized":true', '"authorized":true,"authorized":true'),
    RAW.replace('"method":"GET"', '"method":"GET","factory":"x"'),
])
def test_single_scope_refused_before_contract_or_fixture(raw, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('network reached')
    monkeypatch.setattr(socket, 'socket', forbidden)
    with pytest.raises(SingleScopeError):
        prepare_single_scope(raw)
