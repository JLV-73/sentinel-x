"""Generate offline API responses for SENTINEL_2XX_API_PAYLOADS frontend test.

Run with the project Python: python -B backend/tests/discovery_2xx_api_fixture.py OUTPUT
The transport reads synthetic bytes, and the gated process is simulated in-process.
"""
import json
import sys
from pathlib import Path
from unittest.mock import patch

root = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(root / 'backend'), str(root / 'backend' / 'tests')]
from app import fortress_discovery_transport as transport, fortress_discovery_worker as worker
from test_discovery_observed_exchange import invoke
from test_fortress_discovery_vertical import client_and_auth


def main(output):
    results = []
    for status in (201, 202, 205, 206):
        body = b'' if status == 205 else b'<a href="/next">x</a>'
        extra = f'Content-Range: bytes 0-{len(body)-1}/{len(body)+10}\r\n' if status == 206 else ''
        wire = f'HTTP/1.1 {status} Result\r\nContent-Length: {len(body)}\r\n{extra}Content-Type: text/html\r\n\r\n'.encode() + body
        response = invoke(wire)
        def gated(argv, timeout, payload):
            return json.dumps(worker._discovery_observed_live(json.loads(payload))).encode()
        with patch.object(transport, 'exchange_observed', return_value=response), patch.object(worker, 'run_gated', gated):
            client, auth = client_and_auth()
            answer = client.post('/api/fortress/discovery/live', headers=auth,
                                 json={'authorized': True, 'target': 'https://example.invalid/', 'routes': ['/', '/next']})
            if answer.status_code != 200:
                raise RuntimeError(answer.text)
            results.append(answer.json())
    Path(output).write_text(json.dumps(results), encoding='utf-8')
    print('Generated', len(results), 'synthetic API responses')


if __name__ == '__main__':
    main(sys.argv[1])
