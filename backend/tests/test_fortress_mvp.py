import pytest


def test_real_fixture_tls_and_http():
    from app.fortress_mvp import run_demo
    result = run_demo('ok')
    assert result['mode'] == 'fixture'
    assert result['http_status'] == 200
    assert result['tls']['certificate'] == 'verified'
    assert result['tls']['hostname'] == 'verified'
    assert result['tls']['protocol'].startswith('TLS')
    assert result['failure_code'] == 'none'


def test_public_url_never_opens_network(monkeypatch):
    import socket
    from app.fortress_mvp import diagnose
    def forbidden(*args, **kwargs):
        raise AssertionError('network accessed')
    monkeypatch.setattr(socket, 'getaddrinfo', forbidden)
    monkeypatch.setattr(socket, 'create_connection', forbidden)
    result = diagnose('https://example.org/')
    assert result['failure_code'] == 'not_performed'


def test_operational_route_requires_capability_before_body():
    from fastapi.testclient import TestClient
    from fastapi import FastAPI
    from app.fortress_mvp_api import install_disabled_route
    app = FastAPI()
    install_disabled_route(app, ('http://127.0.0.1:5177',))
    client = TestClient(app, base_url='http://127.0.0.1:8007')
    response = client.post('/api/fortress/audit', headers={'Origin': 'http://127.0.0.1:5177', 'X-Sentinel-Request': 'sync'}, content=b'not JSON')
    assert response.status_code == 403


def test_forbidden_and_tls_failure_are_real_distinct_results():
    from app.fortress_mvp import run_demo
    forbidden = run_demo('forbidden')
    assert forbidden['http_status'] == 403
    assert forbidden['failure_code'] == 'http_refused'
    assert forbidden['tls']['hostname'] == 'verified'
    failed = run_demo('tls-error')
    assert failed['http_status'] is None
    assert failed['failure_code'] == 'tls_or_transport'
    assert failed['tls']['hostname'] == 'indeterminate'
