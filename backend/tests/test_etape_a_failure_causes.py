"""Closed cause codes must describe observations, never exception text."""
from copy import deepcopy
import json
import pytest
from app import fortress_service as service
from app import fortress_standard_contract as contract
from test_fortress_standard_projection_strict import result, PAYLOAD, RAW

@pytest.mark.parametrize('state,status,count,code', [
    ('completed', 200, 1, 'none'), ('redirected', 302, 1, 'none'),
    ('indeterminate', 403, 1, 'http_refused'),
    ('blocked', None, 1, 'security_refused'), ('blocked', None, 1, 'incomplete'),
    ('blocked', None, 1, 'timeout'), ('blocked', None, 1, 'tls_or_transport'),
    ('not_started', None, 0, 'unknown'),
])
def test_project_valid_codes(state, status, count, code):
    report = result()
    report['route_execution'][0]['state'] = state
    report.update(http_status=status, requests_used=count, failure_code=code)
    assert contract.project_strict(report, PAYLOAD)['failure_code'] == code

@pytest.mark.parametrize('state,status,code', [
    ('completed', 200, 'timeout'), ('blocked', None, 'none'),
    ('blocked', None, 'http_refused'), ('redirected', 302, 'incomplete'),
    ('indeterminate', 403, 'none'), ('blocked', None, 'secret raw exception'),
])
def test_project_rejects_inconsistent_codes(state, status, code):
    report = result()
    report['route_execution'][0]['state'] = state
    report.update(http_status=status, failure_code=code)
    with pytest.raises(ValueError):
        contract.project_strict(report, PAYLOAD)

@pytest.mark.parametrize('cause', ['security_refused', 'incomplete', 'timeout', 'tls_or_transport'])
def test_service_preserves_only_bounded_failure_cause(cause):
    class Failure:
        def __init__(self, *args, **kwargs): self.count, self.blocked = 0, False
        def observe_headers(self, *args):
            self.count, self.blocked = 1, True
            return {'outcome': 'error', 'failure_code': cause}
    report = service._audit_single_with_factory(RAW, factory=Failure)
    assert report['http_status'] is None
    assert report['failure_code'] == cause
    assert contract.project_strict(report, PAYLOAD)['failure_code'] == cause

def test_arbitrary_failure_is_never_echoed():
    class Failure:
        def __init__(self, *args, **kwargs): self.count, self.blocked = 0, False
        def observe_headers(self, *args):
            self.count, self.blocked = 1, True
            return {'outcome': 'error', 'failure_code': 'secret raw exception'}
    report = service._audit_single_with_factory(RAW, factory=Failure)
    assert report['failure_code'] == 'unknown'
    assert 'secret raw exception' not in repr(contract.project_strict(report, PAYLOAD))

def test_contradictory_error_observation_cannot_assert_a_cause():
    class Failure:
        def __init__(self, *args, **kwargs): self.count, self.blocked = 0, False
        def observe_headers(self, *args):
            self.count, self.blocked = 1, True
            return {'outcome': 'error', 'failure_code': 'timeout', 'status': 200}
    report = service._audit_single_with_factory(RAW, factory=Failure)
    assert report['failure_code'] == 'unknown'
    assert report['http_status'] is None
