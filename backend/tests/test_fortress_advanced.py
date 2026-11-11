def test_fixture_head_absence_is_a_confirmed_fact_not_a_priority():
    from app.fortress_advanced import analyze_fixture
    report = analyze_fixture(b'HTTP/1.1 200 OK\r\n\r\n')
    assert report['schema_version'] == 'fortress.report/1'
    assert report['provenance'] == {'kind': 'fixture', 'attestation': 'none'}
    assert report['execution']['state'] == 'completed'
    finding = next(f for f in report['findings'] if f['rule_id'] == 'hsts.header_absent.v1')
    assert finding['qualification'] == 'confirmed'
    assert finding['priority'] == 'unclassified'
