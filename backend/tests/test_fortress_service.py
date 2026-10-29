import pytest
from unittest.mock import patch
import app.fortress_service as service
from app.fortress_service import AuditError


def audit(request, *, transport_factory, language='en'):
    # Test-only monkeypatch: the application function accepts no factory.
    with patch.object(service, '_SafeTransport', transport_factory):
        return service._audit(request, language=language)


def test_consent_refused_before_transport_construction():
    calls = []
    with pytest.raises(AuditError, match='invalid audit request'):
        audit({'target': 'https://example.invalid/', 'additional_urls': [], 'level': 'standard', 'authorized': False, 'parameters': []}, transport_factory=lambda *a, **k: calls.append(1))
    assert calls == []

import socket
_REAL_SOCKET = socket.socket
import json
import threading



def payload(**changes):
    result = {'target': 'https://example.invalid/private-secret-path', 'additional_urls': [], 'level': 'standard', 'authorized': True, 'parameters': []}
    result.update(changes)
    return result


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('real network forbidden')
    monkeypatch.setattr(socket, 'getaddrinfo', forbidden)
    monkeypatch.setattr(socket, 'socket', forbidden)


class Fake:
    def __init__(self, scope, *, max_requests):
        assert max_requests == 30
        self.count = 0
        self.blocked = False
        self.calls = []
        self.observations = []

    def observe(self, method, url):
        self.count += 1
        self.calls.append((method, url))
        return self.observations.pop(0) if self.observations else {'outcome': 'ok', 'cookies': {'count': 1, 'missing_secure': 1, 'missing_httponly': 0, 'missing_samesite': 0, 'indeterminate': 0}}


@pytest.mark.parametrize('changes', [
    {'authorized': 1}, {'authorized': 'true'}, {'target': 'http://127.0.0.1/'},
    {'target': 'https://example.invalid/?token=secret'}, {'target': 'https://example.invalid/?'},
    {'target': 'https://example.invalid/%2f'}, {'additional_urls': ['https://other.invalid/']},
    {'additional_urls': ['https://example.invalid/private-secret-path']},
    {'additional_urls': ['https://example.invalid/a'] * 4},
    {'level': 'standard', 'parameters': [{'url': 'https://example.invalid/private-secret-path', 'name': 'q', 'kind': 'reflection'}]},
    {'level': 'deep', 'parameters': [{'url': 'https://other.invalid/', 'name': 'q', 'kind': 'reflection'}]},
    {'level': 'deep', 'parameters': [{'url': 'https://example.invalid/private-secret-path', 'name': 'token', 'kind': 'redirect'}]},
    {'level': 'deep', 'parameters': [{'url': 'https://example.invalid/private-secret-path', 'name': 'q', 'kind': 'other'}]},
    {'level': 'deep', 'parameters': [{'url': 'https://example.invalid/private-secret-path', 'name': 'q', 'kind': 'redirect', 'value': 'secret'}]},
    {'level': 'deep', 'parameters': [{'url': 'https://example.invalid/private-secret-path', 'name': 'q', 'kind': 'redirect'}, {'url': 'https://example.invalid/private-secret-path', 'name': 'Q', 'kind': 'reflection'}]},
    {'level': 'deep', 'parameters': [None]}, {'level': []}, {'unexpected': 'secret'},
])
def test_invalid_requests_fail_before_any_transport(changes):
    calls = []
    with pytest.raises(AuditError) as exc:
        audit(payload(**changes), transport_factory=lambda *a, **k: calls.append(1))
    assert str(exc.value) == 'invalid audit request'
    assert not calls


def test_sequential_get_facts_and_redacted_dto():
    created = []
    def factory(*a, **k):
        created.append(Fake(*a, **k)); return created[-1]
    result = audit(payload(additional_urls=['https://example.invalid/second']), transport_factory=factory)
    assert [x[0] for x in created[0].calls] == ['GET', 'GET']
    assert result['requests_used'] == 2 and result['complete'] is False
    assert len(result['findings']) == 28
    assert [x['status'] for x in result['findings'] if x['id'] == 'cookie_attributes'] == ['attention', 'attention']
    assert all(x['status'] == 'indeterminate' for x in result['findings'] if x['id'] in ('cors', 'redirect', 'reflection', 'version'))
    encoded = json.dumps(result)
    assert 'example.invalid' not in encoded and 'private-secret-path' not in encoded
    assert set(result) == {'audit_id', 'mode', 'started_at', 'finished_at', 'scope', 'requests_used', 'complete', 'findings', 'limitations'}
    assert all(set(f) == {'id','status','severity','reason','evidence','limitations','preconditions','recommendation','reference','method','route','date'} for f in result['findings'])


@pytest.mark.parametrize('observation', [{'outcome': 'blocked'}, {'outcome': 'error'}, {'outcome': 'indeterminate'}, {}])
def test_non_ok_stops_later_routes(observation):
    instances = []
    def factory(*a, **k):
        fake = Fake(*a, **k); fake.observations = [observation]; instances.append(fake); return fake
    result = audit(payload(additional_urls=['https://example.invalid/second']), transport_factory=factory)
    assert len(instances[0].calls) == 1 and result['requests_used'] == 1
    assert all(x['status'] == 'indeterminate' for x in result['findings'])


@pytest.mark.parametrize('cookies', [
    {'count': 0, 'missing_secure': 0, 'missing_httponly': 0, 'missing_samesite': 0, 'indeterminate': 0},
    {'count': 1, 'missing_secure': 0, 'missing_httponly': 0, 'missing_samesite': 0, 'indeterminate': 0},
    {'count': 1, 'missing_secure': 1, 'missing_httponly': 0, 'missing_samesite': 0, 'indeterminate': 1},
    {'count': True, 'missing_secure': 1, 'missing_httponly': 0, 'missing_samesite': 0, 'indeterminate': 0},
])
def test_incomplete_cookie_evidence_does_not_claim_absence(cookies):
    def factory(*a, **k):
        fake = Fake(*a, **k); fake.observations = [{'outcome':'ok', 'cookies': cookies}]; return fake
    result = audit(payload(), transport_factory=factory)
    assert next(x for x in result['findings'] if x['id'] == 'cookie_attributes')['status'] == 'indeterminate'


@pytest.mark.parametrize('parameters', [[], [{'url':'https://example.invalid/private-secret-path','name':'q','kind':'redirect'}], [{'url':'https://example.invalid/private-secret-path','name':'q','kind':'reflection'}]])
def test_deep_mode_rejected_before_transport(parameters):
    calls = []
    with pytest.raises(AuditError, match='deep mode unavailable'):
        audit(payload(level='deep', parameters=parameters), transport_factory=lambda *a, **k: calls.append(1))
    assert not calls


def test_global_nonblocking_lock_and_release_after_error():
    entered = threading.Event(); release = threading.Event(); results = []
    class Slow(Fake):
        def observe(self, method, url):
            entered.set(); assert release.wait(5)
            raise ValueError('secret error')
    t = threading.Thread(target=lambda: results.append(audit(payload(), transport_factory=Slow)))
    t.start(); assert entered.wait(5)
    constructed = []
    try:
        with pytest.raises(AuditError, match='audit unavailable'):
            audit(payload(), transport_factory=lambda *a, **k: constructed.append(1))
        assert not constructed
    finally:
        release.set(); t.join(5)
    assert not t.is_alive() and len(results) == 1
    assert 'secret error' not in json.dumps(results)
    assert audit(payload(), transport_factory=Fake)['requests_used'] == 1


def test_redirect_attempts_count_against_budget_and_halt():
    instances = []
    class RedirectBudget(Fake):
        def observe(self, method, url):
            self.calls.append((method, url)); self.count = 30
            return {'outcome':'error'}
    def factory(*a, **k):
        f = RedirectBudget(*a, **k); instances.append(f); return f
    result = audit(payload(additional_urls=['https://example.invalid/second']), transport_factory=factory)
    assert result['requests_used'] == 30 and len(instances[0].calls) == 1
    assert all(x['status'] == 'indeterminate' for x in result['findings'])


def test_process_mutex_excludes_and_recovers_after_termination():
    import os
    import subprocess
    import sys
    from pathlib import Path
    from app.fortress_service import _acquire_process_mutex, _release_process_mutex
    if os.name != 'nt':
        pytest.skip('Windows mutex implementation')
    backend = str(Path(__file__).resolve().parents[1])
    script = ("import sys,time; sys.path.insert(0,sys.argv[1]); "
              "from app.fortress_service import _acquire_process_mutex; "
              "h=_acquire_process_mutex(); print('READY', flush=True); time.sleep(30)")
    child = subprocess.Popen([sys.executable, '-I', '-B', '-c', script, backend], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert child.stdout.readline().strip() == 'READY'
        with pytest.raises(AuditError, match='audit unavailable'):
            _acquire_process_mutex()
        constructed = []
        with pytest.raises(AuditError, match='audit unavailable'):
            audit(payload(), transport_factory=lambda *a, **k: constructed.append(1))
        assert constructed == []
    finally:
        child.kill()
        child.communicate(timeout=10)
    handle = _acquire_process_mutex()
    _release_process_mutex(handle)


def test_service_has_no_public_factory_injection():
    import inspect
    import app.fortress_service as service
    assert not hasattr(service, 'audit')
    assert 'transport_factory' not in inspect.signature(service._audit).parameters
    assert service.__all__ == ()


def test_disabled_endpoint_never_invokes_service_or_constructs_transport(monkeypatch):
    from fastapi.testclient import TestClient
    from app.main import create_app
    calls = []
    def forbidden(*args, **kwargs):
        calls.append(True)
        raise AssertionError('service must not execute')
    # Windows asyncio creates its own local socket pair; outbound service remains blocked.
    monkeypatch.setattr(socket, 'socket', _REAL_SOCKET)
    monkeypatch.setattr(service, '_audit', forbidden)
    monkeypatch.setattr(service, '_SafeTransport', forbidden)
    client = TestClient(create_app(), base_url='http://127.0.0.1:8007')
    response = client.post('/api/fortress/audit', headers={'Origin': 'http://127.0.0.1:5177', 'X-Sentinel-Request': 'sync'}, json=payload())
    assert response.status_code == 503
    assert response.json() == {'detail': 'Audit unavailable'}
    assert calls == []


def test_factory_exception_is_redacted_and_lock_released():
    def bad(*a, **k):
        raise ValueError('raw secret https://example.invalid')
    result = audit(payload(), transport_factory=bad)
    assert 'secret' not in json.dumps(result) and result['requests_used'] == 0
    assert audit(payload(), transport_factory=Fake)['requests_used'] == 1


def test_query_free_authorized_route_cannot_be_approved_by_real_transport():
    from app.fortress_transport import SafeTransport, TransportError, validate_scope
    route = 'https://example.invalid/path'
    scope = validate_scope(route, [])
    with pytest.raises(TransportError, match='invalid probe approvals'):
        SafeTransport(scope, approved_probes={route: ['q']})
    # Synthesizing a query-bearing route does not make it part of the authorized scope.
    with pytest.raises(TransportError, match='invalid probe approvals'):
        SafeTransport(scope, approved_probes={route + '?q=': ['q']})


def test_transport_observe_has_no_controlled_origin_interface():
    import inspect
    from app.fortress_transport import SafeTransport
    assert list(inspect.signature(SafeTransport.observe).parameters) == ['self', 'method', 'url']


def test_deep_parameter_dot_underscore_collision_rejected_before_transport():
    calls = []
    route = 'https://example.invalid/private-secret-path'
    parameters = [{'url': route, 'name': 'a.b', 'kind': 'reflection'},
                  {'url': route, 'name': 'A_B', 'kind': 'redirect'}]
    with pytest.raises(AuditError, match='invalid audit request'):
        audit(payload(level='deep', parameters=parameters), transport_factory=lambda *a, **k: calls.append(1))
    assert calls == []


def test_mixed_probe_scope_is_rejected_before_any_transport():
    calls = []
    route = 'https://example.invalid/private-secret-path'
    parameters = [{'url': route, 'name': 'q', 'kind': 'reflection'},
                  {'url': 'https://example.invalid/not-approved', 'name': 'next', 'kind': 'redirect'}]
    with pytest.raises(AuditError, match='invalid audit request'):
        audit(payload(level='deep', parameters=parameters), transport_factory=lambda *a, **k: calls.append(1))
    assert calls == []


def test_caller_supplied_ip_field_is_rejected_before_any_transport():
    calls = []
    with pytest.raises(AuditError, match='invalid audit request'):
        audit(payload(level='deep', ip='127.0.0.1'), transport_factory=lambda *a, **k: calls.append(1))
    assert calls == []
