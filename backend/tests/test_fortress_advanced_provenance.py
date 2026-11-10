import copy


def test_imported_synthetic_source_retains_synthetic_limit():
    from app.fortress_advanced import analyze_fixture
    from app.fortress_advanced_adapters import adapt_imported, validate_adapter
    fixture = analyze_fixture(b'HTTP/1.1 200 OK\r\n\r\n')
    result = adapt_imported(fixture)
    assert 'synthetic_only' in result['limits']
    assert result['provenance']['attestation'] == 'none'
    assert validate_adapter(result)
    stripped = copy.deepcopy(result)
    stripped['limits'].remove('synthetic_only')
    assert not validate_adapter(stripped)
