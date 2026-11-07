import json
import socket
import ssl
import pytest
from app import fortress_mvp as m


def test_blank_hsts_is_indeterminate():
    result = m._run_fixture('ok', b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nStrict-Transport-Security: \r\n\r\n')
    assert result['headers']['hsts'] == 'indeterminate'


def test_invalid_cookie_is_not_counted_as_protected():
    result = m._run_fixture('ok', b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nSet-Cookie: =secret; Secure; HttpOnly; SameSite=Lax\r\n\r\n')
    assert result['cookies']['secure'] is None
    assert result['cookies']['httponly'] is None
    assert result['cookies']['samesite'] is None
    assert 'secret' not in json.dumps(result)


def test_complete_redirect_is_not_incomplete():
    result = m._run_fixture('ok', b'HTTP/1.1 302 Found\r\nContent-Length: 0\r\nLocation: https://secret.invalid/\r\n\r\n')
    assert result['http_status'] == 302
    assert result['failure_code'] == 'redirected'
    assert result['headers']['hsts'] == 'indeterminate'
    assert 'secret.invalid' not in json.dumps(result)


def test_internal_engine_rejects_private_dns_before_connect(monkeypatch):
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *args: [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 443))])
    monkeypatch.setattr(socket, 'socket', lambda *args: (_ for _ in ()).throw(AssertionError('connected')))
    result = m.diagnose('https://private.invalid/', authorized=True)
    assert result['failure_code'] != 'not_performed'
    assert result['http_status'] is None


@pytest.mark.parametrize('hsts', ['max-age=no', 'max-age=10; max-age=0', 'max-age=1; includeSubDomains=x'])
def test_invalid_hsts_is_unknown(hsts):
    data = ('HTTP/1.1 200 OK\r\nContent-Length: 0\r\nStrict-Transport-Security: ' + hsts + '\r\n\r\n').encode()
    assert m._run_fixture('ok', data)['headers']['hsts'] == 'indeterminate'


@pytest.mark.parametrize('cookie', ['a=x; Secure; Secure', 'a=x; HttpOnly; HttpOnly', 'a=x; SameSite=Lax; SameSite=Strict', 'a=x; Secure; SameSite=other'])
def test_ambiguous_cookie_is_unknown(cookie):
    data = ('HTTP/1.1 200 OK\r\nContent-Length: 0\r\nSet-Cookie: ' + cookie + '\r\n\r\n').encode()
    result = m._run_fixture('ok', data)
    assert all(result['cookies'][k] is None for k in ('secure', 'httponly', 'samesite'))


@pytest.mark.parametrize('url', ['http://host.invalid', 'https://u:p@host.invalid/', 'https://host.invalid/#fragment', 'https://host.invalid/%zz'])
def test_invalid_url_does_not_resolve(monkeypatch, url):
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *args: pytest.fail('unexpected DNS'))
    assert m.diagnose(url, authorized=True)['http_status'] is None


def test_internal_engine_uses_shared_exchange_with_simulated_public_peer(monkeypatch):
    requests = []
    class Socket:
        def settimeout(self, value): pass
        def connect(self, address): assert address == ('8.8.8.8', 443)
        def getpeername(self): return ('8.8.8.8', 443)
        def close(self): pass
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def getpeercert(self): return {}
        def version(self): return 'TLSv1.3'
        def sendall(self, data): requests.append(data)
        def recv(self, size): return b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n' if len(requests) == 1 and not requests.append(b'received') else b''
    class Context:
        verify_mode = ssl.CERT_REQUIRED
        check_hostname = True
        def wrap_socket(self, client, server_hostname):
            assert server_hostname == 'example.org'
            return client
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *args: [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', 443))])
    monkeypatch.setattr(socket, 'socket', lambda *args: Socket())
    monkeypatch.setattr(ssl, 'create_default_context', lambda: Context())
    result = m.diagnose('https://example.org/path?private=secret', authorized=True)
    assert result['http_status'] == 200
    assert requests[0].startswith(b'GET /path?private=secret HTTP/1.1\r\nHost: example.org\r\n')
    assert 'secret' not in json.dumps(result)
