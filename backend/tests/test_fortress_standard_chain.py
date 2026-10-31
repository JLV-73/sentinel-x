"""Real loopback lab HTTP -> service -> transport -> owned HTTP fixture."""
import http.client
import importlib.util
import json
from pathlib import Path
import socket
import threading
from datetime import datetime

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('standard_lab_chain', ROOT / 'scripts' / 'fortress_standard_lab_server.py')
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)

@pytest.fixture
def server():
    s = lab.LabServer(('127.0.0.1', 0), lab.Handler)
    s.capability = 'test-capability'
    t = threading.Thread(target=s.serve_forever, daemon=True)
    t.start()
    try:
        yield s
    finally:
        s.shutdown()
        s.server_close()
        t.join(3)
        assert not t.is_alive()

def post(server, body, extra=None):
    port = server.server_port
    headers = {'Origin': f'http://127.0.0.1:{port}', 'X-Fortress-CSRF': 'same-origin',
               'X-Fortress-Capability': server.capability, 'Content-Type': 'application/json'}
    headers.update(extra or {})
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=8)
    try:
        conn.request('POST', '/lab/audit', body=json.dumps(body), headers=headers)
        response = conn.getresponse()
        return response.status, json.loads(response.read())
    finally:
        conn.close()

def test_fetch_metadata_cross_site_denied_before_fixture(server, monkeypatch):
    called = []
    monkeypatch.setattr(lab, 'run_scenario', lambda _: called.append(True))
    status, _ = post(server, {'scenario': 'positive', 'route_authorized': True}, {'Sec-Fetch-Site': 'cross-site'})
    assert status == 403
    assert not called

def test_http_chain_changes_with_fixture_bytes(server, monkeypatch):
    def no_dns(*args, **kwargs):
        raise AssertionError('real DNS forbidden')
    monkeypatch.setattr(socket, 'getaddrinfo', no_dns)
    reports = {}
    # HTTPConnection normally resolves even literal IP; connect to lab directly without DNS.
    original = http.client.HTTPConnection.connect
    def direct(conn):
        conn.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.sock.settimeout(conn.timeout)
        conn.sock.connect(('127.0.0.1', conn.port))
    monkeypatch.setattr(http.client.HTTPConnection, 'connect', direct)
    for scenario in ('positive', 'negative', 'indeterminate'):
        status, report = post(server, {'scenario': scenario, 'route_authorized': True})
        assert status == 200
        reports[scenario] = report
        assert report['requests_used'] == 1 and report['complete'] is False
        assert report['started_at'] == report['finished_at'] == 'withheld'
        assert all(f['date'] == 'unknown' for f in report['findings'])
        assert report['limitations']
        serialized = json.dumps(report)
        assert 'lab-secret' not in serialized and lab.HOST not in serialized
    cookies = {name: next(f for f in report['findings'] if f['id'] == 'cookie_attributes')['status'] for name, report in reports.items()}
    assert cookies == {'positive': 'conformant', 'negative': 'attention', 'indeterminate': 'indeterminate'}
    assert reports['indeterminate']['route_execution'][0]['state'] == 'blocked'

@pytest.mark.parametrize('body', [
    {'scenario': 'positive', 'route_authorized': True, 'url': 'http://127.0.0.1/'},
    {'scenario': 'positive', 'route_authorized': True, 'factory': 'x'}, {'scenario': 'positive', 'route_authorized': True, 'host': 'example.com'},
    {'scenario': 'positive'},
    {'scenario': True}, {'scenario': 'other'}, {},
])
def test_http_rejects_user_targets_before_dns(server, monkeypatch, body):
    calls = []
    monkeypatch.setattr(lab, 'run_scenario', lambda _: calls.append(True))
    status, _ = post(server, body)
    assert status == 400
    assert not calls

@pytest.mark.parametrize("authorization", [None, False, 1, "true"])
def test_explicit_fixture_consent_required_before_fixture(server, monkeypatch, authorization):
    calls = []
    monkeypatch.setattr(lab, 'run_scenario', lambda _: calls.append(True))
    status, _ = post(server, {'scenario': 'positive', 'route_authorized': authorization})
    assert status == 400
    assert not calls

def test_explicit_fixture_consent_allows_fixed_scenario(server):
    status, result = post(server, {'scenario': 'positive', 'route_authorized': True})
    assert status == 200
    assert result['requests_used'] == 1
