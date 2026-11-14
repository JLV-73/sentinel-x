import json
import pytest
from app import fortress_discovery_policy as policy
from app.fortress_discovery_contract import valid_live


def test_projection_keeps_observations_and_counts_omitted_relations():
    from test_discovery_observed_exchange import invoke
    obs = invoke(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')['observations']
    now = [0.0]
    def exchange(url, cap, timeout):
        links = [f'/item{i}' for i in range(1000)] if url.endswith('/') else ['/item0'] + [f'/other{i}' for i in range(1000-1)]
        return {'status': 200, 'decoded_bytes': 1, 'links': links, 'location': None, 'observations': obs.copy()}
    def sleep(delay): now[0] += delay
    limits = policy.Limits(pages=2, requests=2, depth=1, interval=1, seconds=30, total_bytes=3145728)
    result = policy.discover_observed('https://example.invalid', ['/'], '/', exchange, limits=limits, clock=lambda: now[0], sleep=sleep, dynamic=True, _live_paths=True, private_view=True)
    result['provenance'] = 'live'
    result['limits'].remove('lab_only')
    assert len(result['pages']) == 2
    assert all(p['observations'] is not None for p in result['pages'])
    assert len(result['relations']) <= 1000
    assert {'from': 'page-1', 'to': 'page-2', 'kind': 'link'} in result['relations']
    assert {'from': 'page-2', 'to': 'page-2', 'kind': 'link'} in result['relations']
    assert result['graph_omitted_relations'] == 2000 - len(result['relations'])
    assert len(result['private_paths']) <= 999
    assert valid_live(result)
    assert len(json.dumps(result, ensure_ascii=True, separators=(',', ':')).encode()) <= 262144


@pytest.mark.parametrize('links,omitted', [(500, 0), (998, 0), (999, 1), (1000, 2)])
def test_node_limit_is_distinct_from_crawl_limit(links, omitted):
    from test_discovery_observed_exchange import invoke
    response = invoke(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
    response['links'] = [f'/privatevalue{i}/a/b/c/d/e/f/g' for i in range(links)]
    limits = policy.Limits(pages=1, requests=1, depth=1, interval=1, seconds=30, total_bytes=3145728)
    value = policy.discover_observed('https://example.invalid', ['/'], '/', lambda *args: response,
        limits=limits, dynamic=True, _live_paths=True, private_view=True)
    value['provenance'] = 'live'
    value['limits'].remove('lab_only')
    assert value['reason'] == 'page_limit'
    assert value.get('graph_omitted_relations', 0) == omitted
    assert len(value['relations']) == links - omitted
    assert len(value['private_paths']) == links - omitted + 1
    assert valid_live(value)
    assert len(json.dumps(value, ensure_ascii=True, separators=(',', ':')).encode()) <= 262144
    assert 'privatevalue' not in json.dumps(value)


def test_simulated_worker_parent_api_preserves_bounded_result(monkeypatch):
    from app import fortress_discovery_worker as worker
    from app import fortress_discovery_transport as transport
    from test_discovery_observed_exchange import invoke
    from test_fortress_discovery_vertical import client_and_auth
    answer = invoke(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
    answer['links'] = [f'/item{i}/a/b/c/d/e/f/g' for i in range(1000)]
    monkeypatch.setattr(transport, 'capture_observed', lambda *args: (answer, {'phase': 'none', 'requests_sent': 1, 'responses_received': 1}))
    def gate(argv, timeout, payload, **kwargs):
        output = json.dumps(worker._discovery_observed_live(json.loads(payload)), ensure_ascii=True, separators=(',', ':')).encode()
        assert len(output) <= kwargs['output_limit']
        return output
    monkeypatch.setattr(worker, 'run_gated', gate)
    client, auth = client_and_auth()
    limits = {'pages': 1, 'requests': 1, 'depth': 1, 'interval': 1, 'page_bytes': 65536, 'total_bytes': 65536, 'seconds': 10}
    for private in (False, True):
        response = client.post('/api/fortress/discovery/live', headers=auth, json={'authorized': True, 'target': 'https://example.invalid/', 'routes': ['/'], 'limits': limits, 'private_view': private})
        assert response.status_code == 200
        value = response.json()
        assert value['pages'][0]['observations']['http_status'] == 200
        assert value['graph_omitted_relations'] == 2
        assert ('private_paths' in value) == private
        assert len(response.content) <= 262144
