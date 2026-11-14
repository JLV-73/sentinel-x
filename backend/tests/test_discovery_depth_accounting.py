from app import fortress_discovery_policy as policy
from app import fortress_discovery_transport as transport
from app.fortress_discovery_contract import valid_lab


def test_depth_exclusions_count_references_after_shorter_path_resolution():
    now = [0.0]
    calls = []
    obs = transport._evidence(200, 1, [], full=True)['evidence']
    links = {'/': ['/a', '/b', '/short'], '/a': ['/deep', '/deep', '/short', '/'],
             '/b': ['/deep'], '/short': []}
    def exchange(url, cap, timeout):
        path = url.removeprefix('https://example.invalid')
        calls.append(path)
        return {'status': 200, 'decoded_bytes': 1, 'links': links[path], 'location': None, 'observations': obs}
    def sleep(delay):
        now[0] += delay
    result = policy.discover_observed('https://example.invalid', ['/'], '/', exchange,
        limits=policy.Limits(pages=5, requests=10, depth=1, interval=1, total_bytes=3145728), dynamic=True, clock=lambda: now[0], sleep=sleep)
    assert calls == ['/', '/a', '/b', '/short']
    assert result['exclusion_reasons']['depth'] == 3
    assert sum(result['exclusion_reasons'].values()) == 3
    assert 'excluded_links:3' in result['limits']
    assert result['reason'] == 'depth_limit' and not result['complete']
    assert len(result['relations']) == 7
    assert valid_lab(result)
    assert '/deep' not in repr(result)


def test_contract_rejects_unreconciled_reason_counts():
    from copy import deepcopy
    obs = transport._evidence(200, 1, [], full=True)['evidence']
    def exchange(*args):
        return {'status': 200, 'decoded_bytes': 1, 'links': [None], 'location': None, 'observations': obs}
    result = policy.discover_observed('https://example.invalid', ['/'], '/', exchange)
    assert result['exclusion_reasons']['unknown'] == 1
    assert valid_lab(result)
    bad = deepcopy(result)
    bad['exclusion_reasons']['unknown'] = 0
    assert not valid_lab(bad)


def test_depth_count_survives_later_transport_failure_without_claiming_unseen_links():
    now = [0.0]
    obs = transport._evidence(200, 1, [], full=True)['evidence']
    def exchange(url, cap, timeout):
        path = url.removeprefix('https://example.invalid')
        if path == '/b':
            raise RuntimeError('fixture failure')
        links = ['/a', '/b'] if path == '/' else ['/deep', '/b']
        return {'status': 200, 'decoded_bytes': 1, 'links': links, 'location': None, 'observations': obs}
    def sleep(delay):
        now[0] += delay
    result = policy.discover_observed('https://example.invalid', ['/'], '/', exchange,
        limits=policy.Limits(pages=5, requests=10, depth=1, interval=1, total_bytes=3145728),
        dynamic=True, clock=lambda: now[0], sleep=sleep)
    assert result['reason'] == 'transport_error' and not result['complete']
    assert result['exclusion_reasons']['depth'] == 1
    assert sum(result['exclusion_reasons'].values()) == 1
    assert 'excluded_links:1' in result['limits'] and valid_lab(result)
