import sys
from pathlib import Path
from app import fortress_discovery_worker as worker
from app.fortress_job import run_gated


def test_production_supervision_private_501(monkeypatch):
    backend = str(Path(__file__).resolve().parents[1])
    code = r'''import sys
sys.path.insert(0,sys.argv[1]); sys.path.insert(0,sys.argv[1]+'/tests')
from app import fortress_discovery_worker as w, fortress_discovery_transport as t
from test_discovery_observed_exchange import invoke
answer=invoke(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
answer['links']=['/item'+str(i) for i in range(500)]
t.exchange_observed=lambda *args: answer
raise SystemExit(w._child())'''
    def gate(argv, timeout, payload, **kwargs):
        assert kwargs.get('output_limit') == 262144
        return run_gated([sys.executable, '-I', '-c', code, backend], timeout, payload, **kwargs)
    monkeypatch.setattr(worker, 'run_gated', gate)
    limits = {'pages': 1, 'requests': 1, 'depth': 1, 'interval': 1, 'page_bytes': 524288, 'total_bytes': 524288, 'seconds': 10}
    result = worker.run_observed_live('https://example.invalid/', ['/'], limits, True)
    assert len(result['private_paths']) == 501
    assert len(result['relations']) == 500
    assert result['pages'][0]['observations'] is not None


def test_supervised_overflow_is_reported_as_capacity_not_scope(monkeypatch):
    import pytest
    def gate(argv, timeout, payload, **kwargs):
        code = "import sys;sys.stdin.buffer.readline();sys.stdout.write('x'*262145)"
        return run_gated([sys.executable, '-I', '-c', code], timeout, payload, **kwargs)
    monkeypatch.setattr(worker, 'run_gated', gate)
    with pytest.raises(RuntimeError, match='output capacity exceeded'):
        worker.run_observed_live('https://example.invalid/', ['/'])
    from test_fortress_discovery_vertical import client_and_auth
    client, auth = client_and_auth()
    response = client.post('/api/fortress/discovery/live', headers=auth,
                           json={'authorized': True, 'target': 'https://example.invalid/', 'routes': ['/']})
    assert response.status_code == 503
    assert response.json()['detail'] == 'Discovery output capacity exceeded; observations unavailable'
