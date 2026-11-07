from fastapi.testclient import TestClient
from app.main import create_app

ORIGIN = 'http://127.0.0.1:5177'
HEADERS = {'Origin': ORIGIN, 'X-Sentinel-Request': 'sync'}


def test_demo_requires_capability_and_performs_real_fixture():
    client = TestClient(create_app(), base_url='http://127.0.0.1:8007')
    response = client.get('/api/fortress/mvp/capability', headers=HEADERS)
    assert response.status_code == 200
    token = response.json()['capability']
    assert client.post('/api/fortress/mvp/demo', headers=HEADERS, json={'scenario':'ok','consent':True}).status_code == 403
    response = client.post('/api/fortress/mvp/demo', headers={**HEADERS, 'X-Sentinel-Capability':token}, json={'scenario':'ok','consent':True})
    assert response.status_code == 200
    assert response.json()['scenario'] == 'ok'
    assert response.json()['target'] == 'https://standard-lab.invalid/'
    assert response.json()['route'] == '/'
    assert response.json()['generated_at']
    assert response.json()['http_status'] == 200
    assert response.json()['tls']['hostname'] == 'verified'


def test_demo_security_boundary():
    from app import fortress_mvp_api
    client = TestClient(create_app(), base_url='http://127.0.0.1:8007')
    token = client.get('/api/fortress/mvp/capability', headers=HEADERS).json()['capability']
    auth = {**HEADERS, 'X-Sentinel-Capability': token, 'Content-Type': 'application/json'}
    valid = b'{"scenario":"ok","consent":true}'
    assert client.get('/api/fortress/mvp/capability').status_code == 403
    assert client.get('/api/fortress/mvp/capability', headers={**HEADERS,'Origin':'https://evil.invalid'}).status_code == 403
    assert client.post('/api/fortress/mvp/demo?x=1', headers=auth, content=valid).status_code == 422
    assert client.post('/api/fortress/mvp/demo', headers=[*auth.items(), ('Origin', ORIGIN)], content=valid).status_code == 403
    assert client.post('/api/fortress/mvp/demo', headers=[*auth.items(), ('Content-Type', 'application/json')], content=valid).status_code == 415
    assert client.post('/api/fortress/mvp/demo', headers={k:v for k,v in auth.items() if k != 'Content-Type'}, content=valid).status_code == 415
    for content in (b'{"scenario":"ok","consent":true,"url":"https://example.org"}',
                    b'{"scenario":"ok","scenario":"forbidden","consent":true}',
                    b'{"scenario":"ok","consent":false}'):
        assert client.post('/api/fortress/mvp/demo', headers=auth, content=content).status_code == 422
    assert client.post('/api/fortress/mvp/demo', headers=auth, content=b'x'*513).status_code == 413
    assert fortress_mvp_api._DEMO_LOCK.acquire(False)
    try:
        assert client.post('/api/fortress/mvp/demo', headers=auth, content=valid).status_code == 409
    finally:
        fortress_mvp_api._DEMO_LOCK.release()
    for scenario, status in [('forbidden',403), ('tls-error',None)]:
        r = client.post('/api/fortress/mvp/demo', headers=auth, json={'scenario':scenario,'consent':True})
        assert r.status_code == 200 and r.json()['http_status'] == status
