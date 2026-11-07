from app import fortress_mvp


def test_fixture_uses_shared_https_engine(monkeypatch):
    original = fortress_mvp._https_exchange
    calls = []
    def wrapped(*args, **kwargs):
        calls.append(True)
        return original(*args, **kwargs)
    monkeypatch.setattr(fortress_mvp, '_https_exchange', wrapped)
    assert fortress_mvp.run_demo('ok')['http_status'] == 200
    assert calls == [True]


def test_public_resolution_rejects_any_private_answer_before_connect(monkeypatch):
    import socket
    import time
    import pytest
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *a: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', 443)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 443)),
    ])
    def forbidden(*args, **kwargs):
        raise AssertionError('must reject before opening socket')
    monkeypatch.setattr(socket, 'socket', forbidden)
    with pytest.raises(ValueError):
        fortress_mvp._public_socket('example.org', time.monotonic() + 1)
