import sys
from pathlib import Path
import os
import pytest
from app import fortress_discovery_worker as worker
from app.fortress_job import run_gated


@pytest.mark.skipif(os.name != 'nt', reason='Windows job fixture')
def test_dynamic_deadline_returns_partial_page_from_real_supervised_child(monkeypatch):
    backend = str(Path(__file__).resolve().parents[1])
    code = r'''import sys,time
sys.path.insert(0,sys.argv[1])
from app import fortress_discovery_worker as w, fortress_discovery_transport as t
time.sleep(.15)  # deterministic startup overhead before the crawl clock
def capture(url, cap, timeout):
    time.sleep(timeout + .03)
    return ({'status': 200, 'incomplete': True, 'partial_headers': {'present': [], 'completeness': 'headers_validated_body_incomplete'}},
            {'phase': 'timeout', 'requests_sent': 1, 'responses_received': 1})
t.capture_observed=capture
raise SystemExit(w._child())'''
    observed = {}
    def gate(argv, timeout, payload, **kwargs):
        import json
        observed.update(timeout=timeout, payload=json.loads(payload), options=kwargs)
        return run_gated([sys.executable, '-I', '-B', '-c', code, backend], timeout, payload, **kwargs)
    monkeypatch.setattr(worker, 'run_gated', gate)
    limits = {'pages': 2, 'requests': 2, 'depth': 1, 'interval': 1,
              'page_bytes': 4096, 'total_bytes': 8192, 'seconds': .7}
    result = worker._run_observed_live('https://example.invalid/', ['/'], limits)
    assert observed['payload']['limits'] == limits
    assert limits['seconds'] < observed['timeout'] <= limits['seconds'] + 10
    assert observed['options']['output_limit'] == 262144
    assert result['reason'] == 'duration_limit' and result['requests'] == 1
    assert result['pages'][0]['state'] == 'incomplete'
    assert result['pages'][0]['status'] == 200
    assert result['diagnostic']['phase'] == 'timeout'


@pytest.mark.skipif(os.name != 'nt', reason='Windows job fixture')
def test_dynamic_deadline_preserves_previously_completed_page(monkeypatch):
    backend = str(Path(__file__).resolve().parents[1])
    code = r'''import sys,time
sys.path.insert(0,sys.argv[1]);sys.path.insert(0,sys.argv[1]+'/tests')
from app import fortress_discovery_worker as w, fortress_discovery_transport as t
from test_discovery_observed_exchange import invoke
time.sleep(.15)
first=invoke(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n');first['links']=['/next']
calls=[0]
def capture(url,cap,timeout):
    calls[0]+=1
    if calls[0]==1:return first, {'phase':'none','requests_sent':1,'responses_received':1}
    time.sleep(timeout+.03)
    return {'status':200,'incomplete':True,'partial_headers':{'present':[],'completeness':'headers_validated_body_incomplete'}}, {'phase':'timeout','requests_sent':1,'responses_received':1}
t.capture_observed=capture
raise SystemExit(w._child())'''
    def gate(argv, timeout, payload, **kwargs):
        return run_gated([sys.executable, '-I', '-B', '-c', code, backend], timeout, payload, **kwargs)
    monkeypatch.setattr(worker, 'run_gated', gate)
    limits = {'pages':2, 'requests':2, 'depth':1, 'interval':1,
              'page_bytes':4096, 'total_bytes':8192, 'seconds':1.6}
    result = worker._run_observed_live('https://example.invalid/', ['/'], limits)
    assert result['reason'] == 'duration_limit' and result['requests'] == 2
    assert [page['state'] for page in result['pages']] == ['complete', 'incomplete']
    assert result['pages'][0]['observations'] is not None
    assert result['pages'][1]['status'] == 200


@pytest.mark.skipif(os.name != 'nt', reason='Windows job fixture')
def test_dynamic_supervisor_still_kills_noncooperative_child(monkeypatch, tmp_path):
    import time
    marker = tmp_path / 'late-effect'
    code = "import sys,time,pathlib;sys.stdin.buffer.readline();time.sleep(12);pathlib.Path(sys.argv[1]).write_text('late')"
    def gate(argv, timeout, payload, **kwargs):
        return run_gated([sys.executable, '-I', '-B', '-c', code, str(marker)], timeout, payload, **kwargs)
    monkeypatch.setattr(worker, 'run_gated', gate)
    limits = {'pages': 1, 'requests': 1, 'depth': 0, 'interval': 1,
              'page_bytes': 4096, 'total_bytes': 4096, 'seconds': .1}
    started = time.monotonic()
    with pytest.raises(TimeoutError, match='job deadline'):
        worker._run_observed_live('https://example.invalid/', ['/'], limits)
    assert time.monotonic() - started < 12
    time.sleep(max(0, 12.5 - (time.monotonic() - started)))
    assert not marker.exists()


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
