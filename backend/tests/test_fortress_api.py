import socket
from fastapi.testclient import TestClient
from app.main import create_app


def test_unverified_transport_is_unavailable_before_dns(monkeypatch):
    def no_network(*args, **kwargs):
        raise AssertionError('network must not be reached')
    monkeypatch.setattr(socket, 'getaddrinfo', no_network)
    client = TestClient(create_app(), base_url='http://127.0.0.1:8007')
    response = client.post('/api/fortress/audit', headers={'Origin': 'http://127.0.0.1:5177', 'X-Sentinel-Request': 'sync'}, json={'target': 'https://example.com/private', 'additional_urls': [], 'level': 'standard', 'authorized': True, 'parameters': []})
    assert response.status_code == 503
    assert response.json() == {'detail': 'Audit unavailable'}


def test_guards_and_fixed_responses(monkeypatch):
    from app.fortress_transport import SafeTransport
    def forbidden(*args, **kwargs):
        raise AssertionError('outbound transport must not be reached')
    monkeypatch.setattr(socket, 'getaddrinfo', forbidden)
    monkeypatch.setattr(SafeTransport, '__init__', forbidden)
    client = TestClient(create_app(), base_url='http://127.0.0.1:8007')
    good = {'Origin': 'http://127.0.0.1:5177', 'X-Sentinel-Request': 'sync'}
    for headers in ({}, {'Origin': 'http://evil.example', 'X-Sentinel-Request': 'sync'},
                    {'Origin': 'http://127.0.0.1:5177'},
                    [('Origin', 'http://127.0.0.1:5177'), ('Origin', 'http://127.0.0.1:5177'), ('X-Sentinel-Request', 'sync')],
                    [('Origin', 'http://127.0.0.1:5177'), ('X-Sentinel-Request', 'sync'), ('X-Sentinel-Request', 'sync')]):
        assert client.post('/api/fortress/audit', headers=headers, content=b'privatevalue').status_code == 403
    assert client.post('/api/fortress/audit', headers={**good, 'Host': 'evil.example'}).status_code == 400
    assert client.post('/api/fortress/audit?x=privatevalue', headers=good).status_code == 422
    for body in (b'', b'not-json-privatevalue', b'{"authorized":false}', b'x' * 100000):
        response = client.post('/api/fortress/audit', headers=good, content=body)
        assert response.status_code == 503
        assert response.json() == {'detail': 'Audit unavailable'}
    assert client.get('/api/fortress/audit', headers=good).status_code == 405
