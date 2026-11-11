import json
from unittest.mock import patch
from fastapi import FastAPI
from fastapi.testclient import TestClient
from app import fortress_mvp_api as api
from app.fortress_advanced_core import analyze_head_facts
from app.fortress_live import result


def test_mock_worker_facts_reach_api_and_bad_schema_is_rejected():
    app = FastAPI()
    api.install_disabled_route(app, ('http://127.0.0.1:5177',))
    client = TestClient(app, base_url='http://127.0.0.1:8007')
    headers = {'Origin': 'http://127.0.0.1:5177', 'X-Sentinel-Request': 'sync'}
    token = client.get('/api/fortress/mvp/capability', headers=headers).json()['capability']
    headers['X-Sentinel-Capability'] = token
    fake = result('https://example.invalid/')
    fake['tls'] = {'certificate':'verified', 'hostname':'verified', 'protocol':'TLSv1.3', 'not_before':'Jan  1 00:00:00 2025 GMT', 'not_after':'Jan  1 00:00:00 2030 GMT'}
    fake['http_status'] = 200
    fake['failure_code'] = 'none'
    fake['headers'] = {k:'absent' for k in fake['headers']}
    fake['headers']['csp'] = 'present'
    policy = b"default-src 'unsafe-inline'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; script-src-elem 'unsafe-inline'; script-src-attr 'unsafe-inline'; style-src-elem 'unsafe-inline'; style-src-attr 'unsafe-inline'"
    fake['advanced'] = analyze_head_facts(b'HTTP/1.1 200 OK\r\nContent-Security-Policy: '+policy+b'\r\nContent-Security-Policy-Report-Only: '+policy+b'\r\nSet-Cookie: a=b\r\n\r\n')
    assert len(json.dumps(fake).encode()) > 4096
    body = {'url':'https://example.invalid/FAKE_PATH', 'consent': True}
    # Mock worker output is synthetic; no DNS or network target is contacted.
    with patch.object(api, 'run_gated', side_effect=lambda *a: json.dumps(fake).encode()):
        response = client.post('/api/fortress/audit', headers=headers, json=body)
        assert response.status_code == 200
        assert response.json()['advanced'] == fake['advanced']
        assert 'FAKE_PATH' not in response.text
        fake['advanced']['schema_version'] = 'invalid'
        assert client.post('/api/fortress/audit', headers=headers, json=body).status_code == 503
