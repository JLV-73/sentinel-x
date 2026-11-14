import json
import os
from copy import deepcopy
from pathlib import Path

from app import fortress_discovery_transport as transport
from app import fortress_discovery_worker as worker
from app.fortress_discovery_contract import valid_live
from test_discovery_observed_exchange import invoke
from test_fortress_discovery_vertical import client_and_auth


def test_304_metadata_reaches_api_without_page_analysis_or_fake_redirect(monkeypatch):
    response = invoke(b'HTTP/1.1 304 Not Modified\r\nContent-Length: 123\r\n'
                      b'Content-Encoding: br\r\nLocation: /next\r\n\r\n')
    assert response['status'] == 304 and response['links'] == [] and response['location'] is None
    monkeypatch.setattr(transport, 'exchange_observed', lambda *args: response)
    monkeypatch.setattr(worker, 'run_gated', lambda argv, timeout, payload, **kwargs:
                        json.dumps(worker._discovery_observed_live(json.loads(payload))).encode())
    client, auth = client_and_auth()
    result = client.post('/api/fortress/discovery/live', headers=auth,
                         json={'authorized': True, 'target': 'https://example.invalid/', 'routes': ['/', '/next']})
    assert result.status_code == 200, result.text
    value = result.json()
    assert valid_live(value)
    assert not value['complete'] and value['requests'] == 1 and value['relations'] == []
    assert value['reason'] == 'unknown'
    assert (value['pages'][0]['status'], value['pages'][0]['state']) == (304, 'incomplete')
    assert value['pages'][0]['observations'] is None and value['pages'][0]['findings'] == []
    for change in ('redirected', 'refused', 'complete', 'observations', 'findings'):
        bad = deepcopy(value)
        if change == 'redirected': bad['pages'][0]['state'] = 'redirected'
        elif change == 'refused': bad['reason'] = 'http_refused'
        elif change == 'complete': bad.update(complete=True, reason='none')
        elif change == 'observations': bad['pages'][0]['observations'] = {'http_status': 304}
        else: bad['pages'][0]['findings'] = [{'evidence': 'absent'}]
        assert not valid_live(bad), change
    if os.environ.get('SENTINEL_304_API_PAYLOAD'):
        Path(os.environ['SENTINEL_304_API_PAYLOAD']).write_text(json.dumps(value), encoding='utf-8')
