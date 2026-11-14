import json
import time
import pytest

from app import fortress_discovery_contract as contract
from app import fortress_discovery_policy as policy
from app import fortress_discovery_transport as transport


class LocalResponse:
    def __init__(self, body, status=200, content_type=b'text/html'):
        self.parts = [b'HTTP/1.1 ' + str(status).encode() + b' OK\r\nContent-Type: ' + content_type + b'\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body, b'']

    def settimeout(self, value):
        pass

    def recv(self, size):
        part = self.parts.pop(0) if self.parts else b''
        if len(part) > size:
            self.parts.insert(0, part[size:])
        return part[:size]


def test_inventory_from_local_html_no_resource_requests_or_secrets(monkeypatch):
    bodies = {
        '/': b'''<a href="/next">next</a><a href="https://outside.invalid/secret">external</a>
          <script src="https://outside.invalid/key?token=SECRET_TOKEN"></script>
          <SCRIPT SRC='/local.js'></SCRIPT><script>SECRET_BODY</script><script src=''></script>
          <link REL='preload StyleSheet' href='https://outside.invalid/SECRET_CSS'>
          <link rel='stylesheet' href='/local.css'><link rel='stylesheet' href=''>
          <link rel='notstylesheet' href='/ignored'><link rel='stylesheet'>''',
        '/next': b'<script src="/third.js"></script>',
    }
    calls = []
    def no_network(*args, **kwargs):
        raise AssertionError('unexpected network access')
    monkeypatch.setattr(transport.socket, 'socket', no_network)
    monkeypatch.setattr(transport.socket, 'getaddrinfo', no_network)
    def exchange(url, cap, timeout):
        path = url.removeprefix('https://example.invalid')
        calls.append(path)
        status, size, links, location, observations, resources = transport._read_response(
            LocalResponse(bodies[path]), time.monotonic() + 5, cap, 'observed', url)
        return dict(status=status, decoded_bytes=size, links=links, location=location,
                    observations=observations, resources=resources)
    now = [0.0]
    def sleep(delay): now[0] += delay
    result = policy.discover_observed('https://example.invalid', ['/'], '/', exchange,
        limits=policy.Limits(pages=3, requests=4, depth=1, interval=1, seconds=10, total_bytes=3145728),
        clock=lambda: now[0], sleep=sleep, dynamic=True)
    assert calls == ['/', '/next']
    assert result['resources'] == [
        {'page': 'page-1', 'kind': 'script', 'count': 2},
        {'page': 'page-1', 'kind': 'stylesheet', 'count': 2},
        {'page': 'page-2', 'kind': 'script', 'count': 1},
    ]
    assert contract.valid_lab(result)
    assert all(secret not in json.dumps(result) for secret in ('SECRET_TOKEN', 'SECRET_BODY', 'SECRET_CSS', 'outside.invalid', '/local.js', '/local.css'))


def test_old_exchange_contract_is_still_accepted_and_does_not_invent_zero():
    evidence = transport._evidence(200, 0, [], full=True)['evidence']
    response = {'status': 200, 'decoded_bytes': 0, 'links': [], 'location': None, 'observations': evidence}
    result = policy.discover_observed('https://example.invalid', ['/'], '/', lambda *args: response)
    assert result['complete'] is True
    assert result['resources'] == []
    assert contract.valid_lab(result)


@pytest.mark.parametrize('resources', [
    {'script': True, 'stylesheet': 0}, {'script': 1001, 'stylesheet': 0},
    {'script': 1, 'stylesheet': 0, 'url': 'SECRET'}, {'script': -1, 'stylesheet': 0},
])
def test_invalid_resource_counts_are_rejected(resources):
    evidence = transport._evidence(200, 0, [], full=True)['evidence']
    response = {'status': 200, 'decoded_bytes': 0, 'links': [], 'location': None,
                'observations': evidence, 'resources': resources}
    result = policy.discover_observed('https://example.invalid', ['/'], '/', lambda *args: response)
    assert result['reason'] == 'incomplete' and result['resources'] == []
    assert 'SECRET' not in json.dumps(result)


def test_resource_overflow_fails_closed():
    body = b'<script src="x"></script>' * 1001
    with pytest.raises(ValueError):
        transport._read_response(LocalResponse(body), time.monotonic() + 5, 512 * 1024,
                                 'observed', 'https://example.invalid/')
