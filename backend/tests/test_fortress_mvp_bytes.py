import json
import pytest
from app.fortress_mvp import _run_fixture


def test_real_response_mutation_and_cookie_secrecy():
    body = b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nSet-Cookie: marker=TOP_SECRET; HttpOnly\r\nConnection: close\r\n\r\n'
    result = _run_fixture('ok', body)
    assert result['headers']['hsts'] == 'absent'
    assert result['cookies']['count'] == 1
    assert result['cookies']['secure'] == 0
    assert 'TOP_SECRET' not in json.dumps(result)


@pytest.mark.parametrize('payload', [b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\na', b'HTTP/1.1 302 Found\r\nContent-Length: 5\r\n\r\n', b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n', b''])
def test_incomplete_response_never_gets_a_status(payload):
    result = _run_fixture('ok', payload)
    assert result['failure_code'] == 'incomplete'
    assert result['http_status'] is None
    assert result['headers']['hsts'] == 'indeterminate'


def test_invalid_header_line_must_not_produce_observation():
    payload = b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nBad Header: value\r\n\r\n'
    result = _run_fixture('ok', payload)
    assert result['http_status'] is None
    assert result['failure_code'] == 'incomplete'
