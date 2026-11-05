"""Change owned response bytes, not the API scenario, and compare findings."""
from test_fortress_standard_chain import server, post, lab


def test_same_scenario_mutated_response_changes_cookie_finding(server, monkeypatch):
    original = lab._fixture_response
    status, before = post(server, {'scenario': 'positive', 'route_authorized': True})
    assert status == 200
    monkeypatch.setattr(lab, '_fixture_response', lambda scenario: original('negative'))
    status, after = post(server, {'scenario': 'positive', 'route_authorized': True})
    assert status == 200
    def cookie(report):
        return next(f['status'] for f in report['findings'] if f['id'] == 'cookie_attributes')
    assert (cookie(before), cookie(after)) == ('conformant', 'attention')
