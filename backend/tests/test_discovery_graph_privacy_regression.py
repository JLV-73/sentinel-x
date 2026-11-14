from copy import deepcopy
import traceback

import pytest
from app import fortress_discovery_transport as transport
from app import fortress_discovery_worker as worker
from app.fortress_discovery_contract import valid_live
from test_discovery_observed_exchange import invoke


def result(monkeypatch):
    answer = invoke(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
    monkeypatch.setattr(transport, 'exchange_observed', lambda *args: answer)
    value = worker._discovery_observed_live({'mode': 'observed_live', 'target': 'https://example.invalid/', 'routes': ['/'], 'limits': {}})
    value['complete'], value['reason'] = False, 'duration_limit'
    value['diagnostic']['phase'] = 'budget'
    assert valid_live(value)
    return value


@pytest.mark.parametrize('relations', [
    [{'from': 'page-1', 'to': 'page-2', 'kind': 'redirect'}],
    [{'from': 'page-1', 'to': 'page-999', 'kind': 'link'}],
    [{'from': 'page-1', 'to': 'page-2', 'kind': 'link'}] * 2,
])
def test_invalid_partial_graph_is_rejected(monkeypatch, relations):
    value = result(monkeypatch)
    value['relations'] = deepcopy(relations)
    assert not valid_live(value)


def test_partial_graph_allows_sequential_unvisited_destination(monkeypatch):
    value = result(monkeypatch)
    value['relations'] = [{'from': 'page-1', 'to': 'page-2', 'kind': 'link'}]
    assert valid_live(value)


def test_duplicate_resource_aggregate_is_rejected(monkeypatch):
    value = result(monkeypatch)
    value['resources'] = [{'page': 'page-1', 'kind': 'script', 'count': 1}] * 2
    assert not valid_live(value)


@pytest.mark.parametrize('failure_mode', ['exception', 'invalid_json', 'invalid_scope'])
def test_worker_failure_trace_does_not_retain_scope(monkeypatch, failure_mode):
    def fail(*args):
        raise ValueError('SECRET_FAILURE')
    if failure_mode == 'exception':
        monkeypatch.setattr(worker, 'run_gated', fail)
    elif failure_mode == 'invalid_json':
        monkeypatch.setattr(worker, 'run_gated', lambda *args: b'{"SECRET_FAILURE":')
    else:
        monkeypatch.setattr(worker, 'validate_live_scope', fail)
    try:
        worker.run_observed_live('https://example.invalid/SECRET_TARGET', ['/SECRET_TARGET'])
    except Exception as error:
        trace = traceback.TracebackException.from_exception(error, capture_locals=True)
        frames = [frame for frame in trace.stack if 'fortress_discovery_worker.py' in frame.filename]
        text = str([(f.name, f.locals) for f in frames]) + str(trace.__cause__) + str(trace.__context__)
        assert 'SECRET_TARGET' not in text
        assert 'SECRET_FAILURE' not in text
    else:
        pytest.fail('expected failure')
