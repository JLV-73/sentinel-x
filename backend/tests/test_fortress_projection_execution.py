"""Contradictory execution cannot establish response-dependent findings."""
import copy
import pytest
from support_fortress_api import _project
from test_fortress_service import payload, Fake, audit


@pytest.mark.parametrize('state', ['blocked', 'redirected', 'indeterminate', 'not_started'])
@pytest.mark.parametrize('cookie_missing', [False, True])
def test_projection_degrades_findings_for_unfinished_route(state, cookie_missing):
    request = payload()
    def factory(*args, **kwargs):
        fake = Fake(*args, **kwargs)
        fake.observations = [{'outcome': 'ok', 'redirected': False,
                              'security_headers': {'hsts': 'absent'},
                              'cookies': {'count': 1, 'missing_secure': int(cookie_missing),
                                          'missing_httponly': 0, 'missing_samesite': 0, 'indeterminate': 0}}]
        return fake
    raw = audit(request, transport_factory=factory)
    cookie = next(f for f in raw['findings'] if f['id'] == 'cookie_attributes')
    assert cookie['status'] == ('attention' if cookie_missing else 'conformant')
    assert next(f for f in raw['findings'] if f['id'] == 'hsts')['status'] == 'attention'
    raw['route_execution'][0]['state'] = state
    projected = _project(raw, request)
    assert all(f['status'] == 'indeterminate' for f in projected['findings'])
    assert all(f['evidence_code'] == 'indeterminate' for f in projected['findings'])


@pytest.mark.parametrize('mutation', ['missing', 'duplicate', 'out_of_range'])
def test_projection_rejects_invalid_execution_shape(mutation):
    request = payload()
    raw = audit(request, transport_factory=Fake)
    if mutation == 'missing':
        raw['route_execution'] = []
    elif mutation == 'duplicate':
        raw['route_execution'].append(copy.deepcopy(raw['route_execution'][0]))
    else:
        raw['route_execution'].append({'route_index': 2, 'state': 'completed'})
    with pytest.raises(ValueError):
        _project(raw, request)
