import pytest


def test_fixture_adapter_preserves_sanitized_fixture_evidence():
    from app.fortress_advanced import analyze_fixture
    from app.fortress_advanced_adapters import adapt_fixture
    source = analyze_fixture(b'HTTP/1.1 200 OK\r\n\r\n')
    result = adapt_fixture(source)
    assert result['schema_version'] == 'fortress.adapter/1'
    assert result['provenance'] == {'declared_kind': 'fixture', 'attestation': 'none'}
    assert result['execution'] == source['execution']
    assert result['findings'] == source['findings']
    assert result['scope'] == source['scope']


@pytest.mark.parametrize('kind', ['live', 'imported'])
def test_external_declared_evidence_cannot_attest_execution_or_findings(kind):
    from app.fortress_advanced import analyze_fixture
    from app import fortress_advanced_adapters as adapters
    source = analyze_fixture(b'HTTP/1.1 200 OK\r\n\r\n')
    result = getattr(adapters, 'adapt_' + kind)(source)
    assert result['provenance'] == {'declared_kind': kind, 'attestation': 'none'}
    assert result['execution'] == {'declared_state': 'completed', 'cause': 'none', 'request_sent': 'unknown'}
    assert result['scope'] == source['scope']
    assert all(f['qualification'] == 'declared_unverified' and f['route_id'] == result['scope']['route_id'] for f in result['findings'])
    assert result['findings'][0]['priority'] == 'unclassified'
    assert 'tls' not in result
    if kind == 'live':
        assert 'synthetic_only' in result['limits']


def test_closed_contract_rejects_secrets_and_untrusted_attestation():
    import copy
    import json
    from app.fortress_advanced import analyze_fixture
    from app.fortress_advanced_adapters import adapt_imported, validate_adapter
    secret = 'SYNTHETIC_SECRET_MARKER_7f1'
    source = analyze_fixture(('HTTP/1.1 200 OK\r\nSet-Cookie: session=' + secret + '; Secure\r\nX-Secret: ' + secret + '\r\n\r\n').encode())
    out = adapt_imported(source)
    assert secret not in json.dumps(out)
    assert validate_adapter(out)
    tampered = copy.deepcopy(out)
    tampered['tls'] = {'certificate': 'verified', 'hostname': 'verified'}
    assert not validate_adapter(tampered)
    tampered = copy.deepcopy(source)
    tampered['observations']['hsts'] = secret
    assert adapt_imported(tampered) == {'error': 'invalid_sanitized_report'}
    assert adapt_imported('{"x":1,"x":2}') == {'error': 'invalid_sanitized_report'}


def test_missing_or_incoherent_evidence_is_not_promoted_to_absence():
    import copy
    from app.fortress_advanced import analyze_fixture
    from app.fortress_advanced_adapters import adapt_live, validate_adapter
    source = analyze_fixture(b'HTTP/1.1 200 OK\r\n\r\n')
    del source['observations']['hsts']
    assert adapt_live(source) == {'error': 'invalid_sanitized_report'}
    source = analyze_fixture(b'HTTP/1.1 200 OK\r\n\r\n')
    out = adapt_live(source)
    out['findings'][0]['route_id'] = 'arbitrary-route'
    assert not validate_adapter(out)
    out = adapt_live(source)
    out['execution']['declared_state'] = 'blocked'
    assert not validate_adapter(out)
