"""Bounded worker output and API handoff, with no network access."""
import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from app import fortress_mvp_api as api
from app.fortress_advanced_core import analyze_head_facts
from app.fortress_job import run_gated
from app.fortress_live import _OUTPUT_LIMIT, result


def large_observation():
    value = result('https://example.invalid/')
    value['tls'] = {'certificate': 'verified', 'hostname': 'verified', 'protocol': 'TLSv1.3',
                    'not_before': 'Jan  1 00:00:00 2025 GMT', 'not_after': 'Jan  1 00:00:00 2030 GMT'}
    value['http_status'], value['failure_code'] = 200, 'none'
    value['headers'] = {key: 'absent' for key in value['headers']}
    value['headers']['csp'] = 'present'
    policy = b"; ".join(name + b" 'unsafe-inline'" for name in
                        (b'default-src', b'script-src', b'style-src', b'script-src-elem',
                         b'script-src-attr', b'style-src-elem', b'style-src-attr'))
    value['advanced'] = analyze_head_facts(b'HTTP/1.1 200 OK\r\nContent-Security-Policy: ' + policy +
        b'\r\nContent-Security-Policy-Report-Only: ' + policy + b'\r\nSet-Cookie: a=b\r\n\r\n')
    return value


def test_real_gated_worker_and_api_accept_large_valid_output():
    value = large_observation()
    assert api._valid_observation(value, value['target'])
    encoded = json.dumps(value, separators=(',', ':')).encode('ascii')
    assert 4096 < len(encoded) <= _OUTPUT_LIMIT
    backend = str(Path(__file__).resolve().parents[1])
    # Real worker and Windows job, with only observe replaced before main starts.
    code = ("import sys,json;sys.path.insert(0,sys.argv[1]);"
            "from app import fortress_live_worker as w;"
            "v=json.loads(sys.argv[2]);w.observe=lambda url:v;raise SystemExit(w.main())")
    def gated(_args, timeout, payload):
        raw = run_gated([sys.executable, '-c', code, backend, encoded.decode('ascii')], timeout, payload)
        assert raw == encoded
        return raw
    with patch.object(api, 'run_gated', side_effect=gated):
        assert api._run_live('https://example.invalid/', value['target']) == value


@pytest.mark.parametrize('size,expected_code', [(_OUTPUT_LIMIT, 0), (_OUTPUT_LIMIT + 1, 1)])
def test_worker_enforces_exact_stdout_byte_boundary(size, expected_code):
    backend = str(Path(__file__).resolve().parents[1])
    # Bypass validation only to exercise the byte boundary with arbitrary padding.
    code = ("import sys,json;sys.path.insert(0,sys.argv[1]);"
            "from app import fortress_live_worker as w,fortress_mvp_api as api;"
            "api._valid_observation=lambda *a:True;"
            "n=int(sys.argv[2])-len(json.dumps({'padding':''},separators=(',',':')));"
            "w.observe=lambda url:{'padding':'x'*n};raise SystemExit(w.main())")
    child = subprocess.run([sys.executable, '-c', code, backend, str(size)],
                           input=b'GO\n\"https://example.invalid/\"', capture_output=True, timeout=10)
    assert child.returncode == expected_code
    assert len(child.stdout) == (size if expected_code == 0 else 0)


def test_api_rejects_output_above_limit():
    with patch.object(api, 'run_gated', return_value=b' ' * (_OUTPUT_LIMIT + 1)):
        with pytest.raises(ValueError, match='Invalid result'):
            api._run_live('https://example.invalid/', 'https://example.invalid/')
