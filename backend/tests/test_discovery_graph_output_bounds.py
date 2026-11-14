import json
import sys

import pytest
from app.fortress_job import run_gated


def test_discovery_supervisor_accepts_501_node_private_output():
    # The real Discovery worker receives 500 synthetic, scope-valid links.
    from pathlib import Path
    backend = str(Path(__file__).resolve().parents[1])
    code = r'''import sys,json
sys.path.insert(0,sys.argv[1]); sys.path.insert(0,sys.argv[1]+'/tests')
from app import fortress_discovery_worker as w, fortress_discovery_transport as t
from test_discovery_observed_exchange import invoke
answer=invoke(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
answer['links']=['/item'+str(i) for i in range(500)]
t.exchange_observed=lambda *args: answer
raise SystemExit(w._child())'''
    limits = {'pages': 1, 'requests': 1, 'depth': 1, 'interval': 1, 'page_bytes': 524288, 'total_bytes': 524288, 'seconds': 10}
    payload = json.dumps({'mode': 'observed_dynamic', 'target': 'https://example.invalid/', 'routes': ['/'], 'limits': limits, 'private_view': True}).encode()
    raw = run_gated([sys.executable, '-I', '-c', code, backend], 20, payload, output_limit=262144)
    result = json.loads(raw)
    from app.fortress_discovery_contract import valid_live
    assert valid_live(result)
    assert result['pages'][0]['observations'] is not None
    assert result['reason'] == 'page_limit'
    assert len(result['relations']) == 500
    assert len(result['private_paths']) == 501
    assert len(raw) > 32768


def test_discovery_output_limit_is_bounded_during_supervision():
    exact = "import sys;sys.stdin.buffer.readline();sys.stdout.write('x'*262144)"
    assert len(run_gated([sys.executable, '-I', '-c', exact], 10, output_limit=262144)) == 262144
    code = "import sys;sys.stdin.buffer.readline();sys.stdout.write('x'*262145)"
    with pytest.raises(ValueError):
        run_gated([sys.executable, '-I', '-c', code], 10, output_limit=262144)
    for invalid in (True, 0, 262145):
        with pytest.raises(ValueError):
            run_gated([sys.executable, '-I', '-c', code], 10, output_limit=invalid)
