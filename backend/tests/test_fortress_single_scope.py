import importlib
import json
import logging
import socket
import traceback

import pytest

from app.fortress_service import _validate
from app.fortress_single_scope import SingleScopeError, prepare_single_scope


def request(url='https://site.invalid/path', authorized=True, method='GET', **extra):
    return json.dumps({'url': url, 'authorized': authorized, 'method': method, **extra})


def test_translates_one_explicitly_authorized_https_get():
    guard = importlib.import_module('app.fortress_single_scope')
    result = guard.prepare_single_scope('{"url":"https://site.invalid/path","authorized":true,"method":"GET"}')
    assert result == {'level': 'standard', 'authorized': True, 'routes': [
        {'url': 'https://site.invalid/path', 'safe_use_confirmed': True,
         'methods': ['GET'], 'cors_get': False, 'parameters': []}]}
    scope, routes, level = _validate(result, 'en')
    assert len(scope.routes) == len(routes) == 1
    assert scope.origin[0] == 'https' and level == 'standard'


@pytest.mark.parametrize('consent', [False, None, 'true', 1, 0, [], {}])
def test_consent_requires_literal_true(consent):
    with pytest.raises(SingleScopeError, match='^invalid single scope$'):
        prepare_single_scope(request(authorized=consent))


@pytest.mark.parametrize('url', [
    'http://site.invalid/path', 'https://user:pass@site.invalid/',
    'https://user@site.invalid/', 'https://127.0.0.1/', 'https://[::1]/',
    'https://192.0.2.1/', 'https://10.0.0.1/', 'https://169.254.169.254/',
    'https://2130706433/', 'https://0x7f000001/', 'https://0177.0.0.1/',
    'https://site.invalid/%2e%2e/admin', 'https://site.invalid/a%2fb',
    'https://site.invalid/#fragment', 'https://site.invalid/?',
    'https://site.invalid/?q=1', 'https://site.invalid/a/../b',
    'https://site.invalid//a', 'https://site.invalid:0443/',
    'https://site.invalid/\nfoo', 'https://site.invalid/a;param',
    ['https://site.invalid/a', 'https://site.invalid/b'],
    'https://site.invalid/a https://other.invalid/b',
])
def test_rejects_unsafe_or_ambiguous_urls(url):
    with pytest.raises(SingleScopeError):
        prepare_single_scope(request(url=url))


@pytest.mark.parametrize('method', ['POST', 'HEAD', 'OPTIONS', 'get', '', None, ['GET'], 1])
def test_get_only(method):
    with pytest.raises(SingleScopeError):
        prepare_single_scope(request(method=method))


@pytest.mark.parametrize('key,value', [
    ('urls', ['https://site.invalid/a', 'https://site.invalid/b']),
    ('routes', []), ('parameters', []), ('params', {}), ('cors', False),
    ('cors_get', False), ('probes', []), ('credentials', None),
    ('headers', {}), ('authorization', ''), ('level', 'standard'),
    ('safe_use_confirmed', True), ('method_override', 'GET'),
])
def test_rejects_any_extra_field_even_disabled(key, value):
    with pytest.raises(SingleScopeError):
        prepare_single_scope(request(**{key: value}))


@pytest.mark.parametrize('raw', [
    '{"url":"https://site.invalid/","url":"https://other.invalid/","authorized":true,"method":"GET"}',
    '{"url":"https://site.invalid/","authorized":false,"authorized":true,"method":"GET"}',
    '{"url":"https://site.invalid/","authorized":true,"method":"GET","method":"GET"}',
    '{"url":"https://site.invalid/","authorized":true}',
    '{"url":"https://site.invalid/","authorized":true,"method":"GET",}',
    '[]', 'null', '', '{}', b'{}', {'url': 'https://site.invalid/'},
])
def test_rejects_duplicate_missing_malformed_and_non_text(raw):
    with pytest.raises(SingleScopeError):
        prepare_single_scope(raw)


def test_no_dns_or_socket_for_acceptance_or_refusal(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('network or DNS attempted')
    monkeypatch.setattr(socket, 'getaddrinfo', forbidden)
    monkeypatch.setattr(socket, 'socket', forbidden)
    assert prepare_single_scope(request())['authorized'] is True
    for value in (request(authorized=False), request(url='https://127.0.0.1/'),
                  request(method='POST'), request(probes=['x'])):
        with pytest.raises(SingleScopeError):
            prepare_single_scope(value)


def test_rejection_and_logs_never_contain_raw_url(caplog):
    secret = 'https://user:secret@site.invalid/private-secret'
    with caplog.at_level(logging.DEBUG):
        with pytest.raises(SingleScopeError) as failure:
            prepare_single_scope(request(url=secret))
    assert str(failure.value) == 'invalid single scope'
    assert secret not in caplog.text and 'private-secret' not in caplog.text
    assert failure.value.__suppress_context__ is True


def test_malformed_json_does_not_retain_sensitive_exception_context():
    raw = '{"url":"https://site.invalid/private-sentinel","authorized":true,'
    with pytest.raises(SingleScopeError) as failure:
        prepare_single_scope(raw)
    assert failure.value.__context__ is None
    assert failure.value.__cause__ is None


@pytest.mark.parametrize('raw', [
    '{"url":"https://site.invalid/private-sentinel","authorized":true,',
    '{"url":"https://site.invalid/private-sentinel","url":"https://site.invalid/",'
    '"authorized":true,"method":"GET"}',
    request(url='https://site.invalid/private-sentinel', authorized=False),
    request(url='https://site.invalid/?token=private-sentinel'),
    request(credentials={'token': 'private-sentinel'}),
    '{"url":"https://site.invalid/","authorized":true,"method":"GET",'
    '"extra":{"x":"private-sentinel","x":2}}',
])
def test_refusal_does_not_leak_sensitive_data(raw, caplog):
    with caplog.at_level(logging.ERROR):
        try:
            prepare_single_scope(raw)
        except SingleScopeError as error:
            logging.getLogger(__name__).exception('refused')
            assert error.__context__ is None and error.__cause__ is None
            for name in dir(error):
                if name == '__traceback__':
                    continue
                assert 'private-sentinel' not in repr(getattr(error, name))
            assert 'private-sentinel' not in repr(error)
            assert 'private-sentinel' not in ''.join(traceback.format_exception(error))
            frame = error.__traceback__
            while frame:
                if frame.tb_frame.f_code.co_name == 'prepare_single_scope':
                    assert 'private-sentinel' not in repr(frame.tb_frame.f_locals)
                frame = frame.tb_next
        else:
            pytest.fail('expected refusal')
    assert 'private-sentinel' not in caplog.text


@pytest.mark.parametrize('error', [KeyboardInterrupt, SystemExit, GeneratorExit])
def test_system_base_exceptions_propagate(monkeypatch, error):
    guard = importlib.import_module('app.fortress_single_scope')
    def abort(*args, **kwargs):
        raise error()
    monkeypatch.setattr(guard, '_parse', abort)
    with pytest.raises(error):
        prepare_single_scope(request())


def test_unexpected_validation_exception_stays_fail_closed(monkeypatch):
    guard = importlib.import_module('app.fortress_single_scope')
    def fail(*args, **kwargs):
        raise RuntimeError('private-sentinel')
    monkeypatch.setattr(guard, '_validate', fail)
    with pytest.raises(SingleScopeError) as failure:
        prepare_single_scope(request())
    assert failure.value.__context__ is None
    assert 'private-sentinel' not in repr(failure.value)