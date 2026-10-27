"""Offline tests must never fall through to HTTPX's real network transport."""
import httpx
import pytest


@pytest.fixture(autouse=True)
def deny_live_http(monkeypatch):
    def blocked(*args, **kwargs):
        pytest.fail("Live HTTP is forbidden in backend tests; inject MockTransport")
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", blocked)
