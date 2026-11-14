import gzip
import pytest
from app import fortress_discovery_contract as contract, fortress_discovery_policy as policy
from test_discovery_observed_exchange import invoke

P = {'present': ['strict-transport-security'], 'completeness': 'headers_validated_body_incomplete'}

@pytest.mark.parametrize('status', [200, 302])
def test_length_over_budget_preserves_attested_headers(status):
    wire = (b'HTTP/1.1 ' + str(status).encode() + b' Test\r\nStrict-Transport-Security: SECRET\r\n'
            b'Location: /next\r\nContent-Type: text/html\r\nContent-Length: 1001\r\n\r\n')
    assert invoke(wire) == {'status': status, 'incomplete': True, 'partial_headers': P}


def test_gzip_decoded_budget_preserves_attested_headers():
    body = gzip.compress(b'SECRET_BODY' * 200)
    wire = (b'HTTP/1.1 200 OK\r\nStrict-Transport-Security: SECRET\r\nContent-Type: text/html\r\n'
            b'Content-Encoding: gzip\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)
    assert invoke(wire) == {'status': 200, 'incomplete': True, 'partial_headers': P}

@pytest.mark.parametrize('status', [200, 302])
def test_deadline_preserves_partial_page_without_followup(status):
    now = [0.0]
    calls = []
    def exchange(*args):
        calls.append(args)
        now[0] = 121.0
        return {'status': status, 'incomplete': True, 'partial_headers': P}
    result = policy.discover_observed('https://example.invalid', ['/'], '/', exchange, clock=lambda: now[0], _live_paths=True)
    assert result['reason'] == 'duration_limit'
    assert result['requests'] == len(calls) == 1
    assert len(result['pages']) == 1
    page = result['pages'][0]
    assert (page['status'], page['state'], page['partial_headers']) == (status, 'incomplete', P)
    assert page['observations'] is None and page['findings'] == [] and result['relations'] == []
    result['provenance'] = 'live'
    result['limits'].remove('lab_only')
    result['diagnostic'] = {'phase': 'budget', 'requests_sent': 1, 'responses_received': 1}
    assert contract.valid_live(result)


def test_deadline_through_worker_and_asgi(monkeypatch):
    import json
    from app import fortress_discovery_transport as transport, fortress_discovery_worker as worker
    from test_fortress_discovery_vertical import client_and_auth
    now = [0.0]
    calls = []
    original = policy.discover_observed
    def timed_policy(*args, **kwargs):
        return original(*args, **kwargs, clock=lambda: now[0])
    def capture(*args):
        calls.append(args)
        now[0] = 121.0
        return ({'status': 302, 'incomplete': True, 'partial_headers': P},
                {'phase': 'timeout', 'requests_sent': 1, 'responses_received': 1})
    monkeypatch.setattr(policy, 'discover_observed', timed_policy)
    monkeypatch.setattr(transport, 'capture_observed', capture)
    monkeypatch.setattr(worker, 'run_gated', lambda argv, timeout, payload:
                        json.dumps(worker._discovery_observed_live(json.loads(payload))).encode())
    client, auth = client_and_auth()
    response = client.post('/api/fortress/discovery/live', headers=auth,
                           json={'authorized': True, 'target': 'https://example.invalid/', 'routes': ['/']})
    assert response.status_code == 200, response.text
    value = response.json()
    assert value['reason'] == 'duration_limit'
    assert value['diagnostic'] == {'phase': 'timeout', 'requests_sent': 1, 'responses_received': 1}
    assert len(calls) == value['requests'] == 1
    assert value['pages'][0]['status'] == 302 and value['pages'][0]['state'] == 'incomplete'
    assert value['pages'][0]['partial_headers'] == P
    assert value['relations'] == [] and value['pages'][0]['observations'] is None
    assert contract.valid_live(value)
