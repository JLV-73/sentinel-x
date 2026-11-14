from copy import deepcopy
import json

import pytest
from app import fortress_discovery_policy as policy
from app import fortress_discovery_transport as transport
from app import fortress_discovery_worker as worker
from app.fortress_discovery_contract import valid_live
from test_discovery_observed_exchange import invoke
from test_fortress_discovery_vertical import client_and_auth


def live(monkeypatch, routes):
    answer = invoke(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
    answer['links'] = routes[1:]
    monkeypatch.setattr(transport, 'exchange_observed', lambda *args: answer if args[0].endswith(routes[0]) else {**answer, 'links': []})
    return worker._discovery_observed_live({'mode': 'observed_live', 'target': 'https://example.invalid' + routes[0], 'routes': routes, 'limits': {}})


def test_live_sanitizes_paths_without_losing_page_identity(monkeypatch):
    result = live(monkeypatch, ['/products', '/foo-SECRET_TOKEN', '/secret/SECRET_TOKEN', '/other-SECRET_TOKEN'])
    assert [(p['id'], p['route']) for p in result['pages']] == [
        ('page-1', '/{segment}'), ('page-2', '/{segment}'),
        ('page-3', '/{segment}/{segment}'), ('page-4', '/{segment}')]
    assert all(f['route'] == p['route'] for p in result['pages'] for f in p['findings'])
    assert {r['to'] for r in result['relations']} == {'page-2', 'page-3', 'page-4'}
    assert 'SECRET_TOKEN' not in json.dumps(result)
    assert valid_live(result)


def test_live_projection_id_and_scope_denial(monkeypatch):
    result = live(monkeypatch, ['/products/123'])
    assert result['pages'][0]['route'] == '/{segment}/{segment}'
    with pytest.raises(ValueError):
        worker.validate_live_scope('https://example.invalid/api', ['/api'])


def test_parent_rejects_untrusted_paths_and_finding_mismatch(monkeypatch):
    result = live(monkeypatch, ['/products'])
    assert valid_live(result)
    for route in [123, True, None, '/login', '/account', '/products', '/{id}', '/products/{segment}', '/products/123', '/foo-SECRET_TOKEN', '/products?SECRET_TOKEN', '/<script>alert(1)</script>', '/products#x', '/products/', '/' + '/'.join(['products'] * 21)]:
        bad = deepcopy(result)
        bad['pages'][0]['route'] = route
        for finding in bad['pages'][0]['findings']:
            finding['route'] = route
        assert not valid_live(bad)
    bad = deepcopy(result)
    bad['pages'][0]['path'] = '/products'
    assert not valid_live(bad)
    bad = deepcopy(result)
    bad['pages'][0]['findings'][0]['route'] = 'page-1'
    assert not valid_live(bad)


def test_old_live_alias_contract_remains_accepted(monkeypatch):
    result = live(monkeypatch, ['/products'])
    result['pages'][0]['route'] = 'page-1'
    for finding in result['pages'][0]['findings']:
        finding['route'] = 'page-1'
    assert valid_live(result)


def test_api_parent_accepts_safe_projection_only(monkeypatch):
    answer = invoke(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
    monkeypatch.setattr(transport, 'exchange_observed', lambda *args: answer)
    monkeypatch.setattr(worker, 'run_gated', lambda argv, timeout, payload:
                        json.dumps(worker._discovery_observed_live(json.loads(payload))).encode())
    client, auth = client_and_auth()
    result = client.post('/api/fortress/discovery/live', headers=auth, json={
        'authorized': True, 'target': 'https://example.invalid/products/123', 'routes': ['/products/123']})
    assert result.status_code == 200
    assert result.json()['pages'][0]['route'] == '/{segment}/{segment}'
    assert result.json()['pages'][0]['id'] == 'page-1'
    assert '123' not in result.text and 'example.invalid' not in result.text


def test_root_and_sensitive_homonyms_collide_only_in_display(monkeypatch):
    result = live(monkeypatch, ['/', '/login', '/account', '/123456789', '/credentialFAKEsecret'])
    assert [p['route'] for p in result['pages']] == ['/', *(['/{segment}'] * 4)]
    assert [p['id'] for p in result['pages']] == [f'page-{i}' for i in range(1, 6)]
    assert {r['to'] for r in result['relations']} == {f'page-{i}' for i in range(2, 6)}
    for page in result['pages']:
        assert page['findings'] and all(f['route'] == page['route'] for f in page['findings'])
    serialized = json.dumps(result)
    for secret in ('/login', '/account', '123456789', 'credentialFAKEsecret'):
        assert secret not in serialized
    assert valid_live(result)


def test_rejected_links_are_counted_without_leaking_or_being_requested(monkeypatch):
    answer = invoke(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
    links = ['/login%2FencodedSECRET', '/<script>XSSsecret</script>',
             'https://userFAKE:passwordFAKE@example.invalid/privateSECRET',
             '/outsideSECRET?token=querySECRET']
    answer['links'] = links
    calls = []
    def exchange(url, *args):
        calls.append(url)
        return answer
    monkeypatch.setattr(transport, 'exchange_observed', exchange)
    result = worker._discovery_observed_live({'mode': 'observed_live', 'target': 'https://example.invalid/', 'routes': ['/'], 'limits': {}})
    assert calls == ['https://example.invalid/']
    assert 'excluded_links:4' in result['limits']
    assert not result['complete']
    for secret in ('encodedSECRET', 'XSSsecret', 'userFAKE', 'passwordFAKE', 'privateSECRET', 'outsideSECRET', 'querySECRET'):
        assert secret not in json.dumps(result)
    assert valid_live(result)


def test_long_projection_is_collapsed_not_truncated_to_raw_text():
    assert policy._safe_display_path('/') == '/'
    assert policy._safe_display_path('/' + '/'.join(['unknown'] * 12)) == '/{segment}' * 12
    assert policy._safe_display_path('/' + '/'.join(['unknown'] * 13)) == '/{segment}'
    assert policy._safe_display_path('/' + '/'.join(['products'] * 21)) == '/{segment}'
    assert policy._safe_display_path('/' + '/'.join(['unknown'] * 15)) == '/{segment}'
