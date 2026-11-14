"""Offline tests for the observed-response traversal contract."""
from app import fortress_discovery_transport as transport
from app import fortress_discovery_policy as policy
from app import fortress_advanced_core as core
from test_discovery_observed_exchange import invoke


def test_valid_204_keeps_complete_header_observations_in_traversal():
    response = invoke(b'HTTP/1.1 204 No Content\r\nX-Content-Type-Options: nosniff\r\n\r\n')
    assert response['status'] == 204 and response['decoded_bytes'] == 0
    assert response['links'] == [] and response['location'] is None
    assert set(response['observations']) == set(core.empty())
    assert response['observations']['x_content_type_options'] == 'present'
    result = policy.discover_observed('https://example.invalid', ['/'], '/', lambda *args: response)
    assert result['reason'] == 'none' and result['complete']
    assert result['requests'] == 1 and result['bytes'] == 0
    assert len(result['pages']) == 1 and result['pages'][0]['state'] == 'complete'
    assert result['pages'][0]['status'] == 204 and result['relations'] == []
    assert result['pages'][0]['observations'] == response['observations']
    from app.fortress_discovery_contract import valid_lab
    assert valid_lab(result)


def test_scope_exclusion_stays_partial_in_lab_contract():
    from app.fortress_discovery_contract import valid_lab
    response = invoke(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
    response['links'] = ['/outside']
    raw = policy.discover('https://example.invalid', ['/'], '/',
                          lambda *args: {k: response[k] for k in ('status', 'decoded_bytes', 'links', 'location')})
    assert raw['reason'] == 'scope_blocked' and not raw['complete']
    result = policy.discover_observed('https://example.invalid', ['/'], '/', lambda *args: response)
    assert result['reason'] == 'unknown' and not result['complete']
    assert 'excluded_links:1' in result['limits']
    assert len(result['pages']) == 1 and valid_lab(result)
    assert '/outside' not in repr(result)


def test_observed_exchange_has_full_core_projection():
    result = invoke(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Content-Type-Options: nosniff\r\n\r\n')
    assert set(result['observations']) == set(core.empty())
    assert result['observations']['x_content_type_options'] == 'present'


def test_observed_traversal_has_safe_page_findings_and_relations():
    response = invoke(b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 21\r\n\r\n<a href="/next">x</a>')
    assert response
    calls = []
    def exchange(url, cap, timeout):
        calls.append(url)
        return response if url.endswith('/') else invoke(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
    class Clock:
        value = 0
        def __call__(self): return self.value
        def sleep(self, delay): self.value += delay
    clock = Clock()
    result = policy.discover_observed('https://example.invalid', ['/', '/next'], '/', exchange, clock=clock, sleep=clock.sleep)
    assert result['schema'] == 'fortress.discovery/1'
    assert len(result['pages']) == 2
    assert result['relations'] == [{'from':'page-1', 'to':'page-2', 'kind':'link'}]
    assert result['pages'][0]['findings']
    assert 'example.invalid' not in repr(result) and '/next' not in repr(result)


def test_worker_uses_observed_transport_with_fixed_offline_scope(monkeypatch):
    from app import fortress_discovery_worker as worker
    response = invoke(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
    calls = []
    monkeypatch.setattr(worker, '_guard_network', lambda: None)
    monkeypatch.setattr(transport, 'exchange_observed', lambda *args: calls.append(args) or response)
    data = {'mode': 'observed_lab', 'origin': 'https://example.invalid', 'routes': ['/'], 'start': '/', 'limits': {}}
    result = worker._discovery_observed_lab(data)
    assert len(calls) == 1
    assert result['pages'][0]['observations']['http_status'] == 200
    from app.fortress_discovery_contract import valid_lab
    assert valid_lab(result)


def test_partial_403_and_excluded_link_keep_secrets_out():
    ok = invoke(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
    denied = invoke(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n')
    ok['links'] = ['/next', '/private?token=SECRET']
    calls = []
    def exchange(url, cap, timeout):
        calls.append(url)
        return ok if url.endswith('/') else denied
    class Clock:
        value = 0
        def __call__(self): return self.value
        def sleep(self, delay): self.value += delay
    clock = Clock()
    result = policy.discover_observed('https://example.invalid', ['/', '/next'], '/', exchange, clock=clock, sleep=clock.sleep)
    assert len(calls) == 2
    assert result['reason'] == 'http_refused' and not result['complete']
    assert result['pages'][1]['state'] == 'access_denied'
    assert result['pages'][1]['observations'] is None and result['pages'][1]['findings'] == []
    assert 'SECRET' not in repr(result) and '/private' not in repr(result)


def test_observed_worker_job_is_offline_and_returns_valid_partial():
    from app import fortress_discovery_worker as worker
    result = worker.run_observed_lab('https://example.invalid', ['/'], '/', limits=policy.Limits(seconds=5), timeout=10)
    assert result['schema'] == 'fortress.discovery/1'
    assert result['complete'] is False and result['requests'] == 1
    assert result['pages'] == []
    from app.fortress_discovery_contract import valid_lab
    assert valid_lab(result)
