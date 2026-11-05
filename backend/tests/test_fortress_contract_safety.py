"""Offline synthetic ASGI regression tests; not a proxy framing guarantee."""
import json
import pytest
from app.fortress_standard_contract import DraftFortressAdapter
from test_fortress_api_qualification import GOOD_HEADERS, SECRET, request_payload, run_request
from support_fortress_api import fake_audit_result


def test_sentinel_is_not_a_valid_audit_result(monkeypatch):
    response = run_request(DraftFortressAdapter(lambda _: {'ok': True}), monkeypatch=monkeypatch)
    assert response.status_code == 503
    assert response.json() == {'error': 'unavailable'}


@pytest.mark.parametrize('bad_result', [None, {'ok': True, 'secret': SECRET},
                                        {'error': SECRET}, [SECRET]])
def test_invalid_consumer_results_fail_closed(monkeypatch, bad_result):
    response = run_request(DraftFortressAdapter(lambda _: bad_result), monkeypatch=monkeypatch)
    assert response.status_code == 503 and response.json() == {'error': 'unavailable'}
    assert SECRET not in response.text


def test_extra_field_on_real_shaped_result_fails_closed(monkeypatch):
    def consumer(payload):
        result = fake_audit_result(payload)
        result['secret'] = SECRET
        return result
    response = run_request(DraftFortressAdapter(consumer), monkeypatch=monkeypatch)
    assert response.status_code == 503 and response.json() == {'error': 'unavailable'}
    assert SECRET not in response.text


def test_invalid_route_does_not_read_body_or_call_consumer():
    import asyncio
    calls, sent = [], []
    async def receive():
        calls.append('body')
    async def send(message):
        sent.append(message)
    scope = {'type': 'http', 'path': '/api/fortress/other', 'method': 'POST', 'headers': []}
    asyncio.run(DraftFortressAdapter(lambda _: calls.append('consumer'))(scope, receive, send))
    assert sent[0]['status'] == 404 and calls == []


@pytest.mark.parametrize('framing', [
    [('transfer-encoding', 'chunked')],
    [('transfer-encoding', 'chunked'), ('content-length', '1')],
    [('transfer-encoding', 'identity')],
    [('transfer-encoding', ''), ('transfer-encoding', 'chunked')],
    [('content-length', '1'), ('content-length', '1')],
    [('content-length', '1, 1')],
])
def test_invalid_framing_rejected_before_body_or_consumer(framing):
    import asyncio
    calls = []
    sent = []
    async def receive():
        calls.append('body')
        return {'type': 'http.request', 'body': json.dumps(request_payload()).encode()}
    async def send(message):
        sent.append(message)
    scope = {'type': 'http', 'path': '/api/fortress/audit', 'method': 'POST',
             'headers': [(k.encode(), v.encode()) for k, v in GOOD_HEADERS + framing], 'query_string': b''}
    asyncio.run(DraftFortressAdapter(lambda _: calls.append('consumer'))(scope, receive, send))
    assert sent[0]['status'] == 400
    assert calls == []
    assert SECRET not in str(sent)
