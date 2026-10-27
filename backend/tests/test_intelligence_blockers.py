"""Offline regressions for the three independently reproduced P1-A blockers."""
from contextlib import closing
from datetime import timedelta
import gzip
import json
import sqlite3

import httpx
import pytest

from app.intelligence import IntelligenceBusy, IntelligenceFailure, IntelligenceService
from app.sourceclients import SourceClient
from test_backend import api, HEADERS, NOW
from test_intelligence_api import enriched_api
from test_intelligence_clients import CVE, nvd_document, epss_document
from test_intelligence_storage import intelligence


@pytest.fixture(scope="module")
def gzip_bomb():
    # Lazily delivered wire bytes, not Response(content=...) which HTTPX
    # eagerly decodes before the source reader can inspect headers.
    return gzip.compress(b" " * (32 * 1024 * 1024))


@pytest.mark.parametrize("source", ["nvd", "epss"])
@pytest.mark.parametrize("encoding", ["gzip", "x-gzip", "deflate", "br", "identity, gzip", "unknown"])
def test_compressed_response_rejected_before_reading(source, encoding, gzip_bomb):
    consumed, closed, requests, received = [], [], [], []
    class Encoded(httpx.SyncByteStream):
        def __iter__(self):
            consumed.append(True)
            yield gzip_bomb
        def close(self):
            closed.append(True)
    def handler(request):
        requests.append(request)
        return httpx.Response(200, headers={"Content-Encoding": encoding,
            "Content-Length": str(len(gzip_bomb))}, stream=Encoded())
    client = SourceClient()
    client.transport = httpx.MockTransport(handler)
    with pytest.raises(ValueError, match="Content-Encoding"):
        client.request(source, [CVE], on_response=lambda response: received.append(response.status_code))
    assert consumed == [] and closed == [True]
    assert requests[0].headers["accept-encoding"] == "identity"
    assert received == [200]


@pytest.mark.parametrize("source", ["nvd", "epss"])
def test_compressed_429_keeps_retry_after_without_reading(intelligence, source, gzip_bomb):
    service, cisa = intelligence
    consumed = []
    class Encoded(httpx.SyncByteStream):
        def __iter__(self):
            consumed.append(True)
            yield gzip_bomb
    service.client.transport = httpx.MockTransport(lambda request: httpx.Response(429,
        headers={"Content-Encoding": "gzip", "Retry-After": "3600"}, stream=Encoded()))
    fetch = lambda: service.fetch_nvd(CVE, refresh=True) if source == "nvd" else service.fetch_epss()
    with pytest.raises(IntelligenceFailure) as failed:
        fetch()
    assert "Content-Encoding" in failed.value.attempt["error"]
    assert consumed == []
    cisa.clock = lambda: NOW + timedelta(seconds=121)
    with pytest.raises(IntelligenceBusy, match="cooldown"):
        fetch()


def source_document(source, newer=False):
    doc = nvd_document(scores=not newer) if source == "nvd" else epss_document()
    if newer and source == "nvd":
        doc["vulnerabilities"][0]["cve"]["lastModified"] = "2026-10-26T01:02:03.000"
    elif newer:
        doc["data"][0].update(epss="0.5", date="2026-10-26")
    return doc


def fetch_source(service, source):
    return service.fetch_nvd(CVE, refresh=True) if source == "nvd" else service.fetch_epss()


@pytest.mark.parametrize("source", ["nvd", "epss"])
@pytest.mark.parametrize("old_failure", [False, True])
def test_superseded_success_or_failure_cannot_replace_newer_result(intelligence, monkeypatch, source, old_failure):
    service, cisa = intelligence
    replacement = IntelligenceService(cisa)
    service.client.transport = httpx.MockTransport(lambda request: httpx.Response(200,
        content=b"invalid JSON" if old_failure else json.dumps(source_document(source)).encode()))
    replacement.client.transport = httpx.MockTransport(lambda request: httpx.Response(200, json=source_document(source, newer=True)))
    raw, winner = service._raw, {}
    def paused(source_name, fetched):
        provenance = raw(source_name, fetched)
        cisa.clock = lambda: NOW + timedelta(seconds=121)
        fetch_source(replacement, source)
        winner.update(replacement.get(CVE)[source])
        return provenance
    monkeypatch.setattr(service, "_raw", paused)
    with pytest.raises(IntelligenceBusy, match="lease.*(superseded|expired)"):
        fetch_source(service, source)
    assert service.get(CVE)[source] == winner
    assert len(service.status()[source]["history"]) == 1
    assert winner["state"] == "available" and winner["last_attempt"] == winner["last_success"]
    assert winner["data"]["cvss"] == [] if source == "nvd" else winner["data"]["epss"] == 0.5


@pytest.mark.parametrize("source", ["nvd", "epss"])
def test_failure_journal_fallback_is_also_fenced(intelligence, monkeypatch, source):
    service, cisa = intelligence
    replacement = IntelligenceService(cisa)
    service.client.transport = httpx.MockTransport(lambda request: httpx.Response(200, json=source_document(source)))
    replacement.client.transport = httpx.MockTransport(lambda request: httpx.Response(200, json=source_document(source, newer=True)))
    store, winner, calls = service._store, {}, []
    def failed_store(*args, **kwargs):
        calls.append(True)
        if len(calls) == 1:
            cisa.clock = lambda: NOW + timedelta(seconds=121)
            fetch_source(replacement, source)
            winner.update(replacement.get(CVE)[source])
            raise sqlite3.OperationalError("injected original commit failure")
        return store(*args, **kwargs)
    monkeypatch.setattr(service, "_store", failed_store)
    with pytest.raises(IntelligenceBusy, match="lease.*(superseded|expired)"):
        fetch_source(service, source)
    assert len(calls) == 2
    assert service.get(CVE)[source] == winner
    assert len(service.status()[source]["history"]) == 1


@pytest.mark.parametrize("source", ["nvd", "epss"])
@pytest.mark.parametrize("elapsed,accepted", [(119.999, True), (120, False), (121, False)])
def test_commit_requires_unexpired_lease_even_without_replacement(intelligence, monkeypatch, source, elapsed, accepted):
    service, cisa = intelligence
    service.client.transport = httpx.MockTransport(lambda request: httpx.Response(200, json=source_document(source)))
    raw = service._raw
    def paused(*args):
        provenance = raw(*args)
        cisa.clock = lambda: NOW + timedelta(seconds=elapsed)
        return provenance
    monkeypatch.setattr(service, "_raw", paused)
    if accepted:
        fetch_source(service, source)
        assert service.get(CVE)[source]["state"] == "available"
    else:
        with pytest.raises(IntelligenceBusy, match="lease.*expired"):
            fetch_source(service, source)
        assert service.get(CVE)[source]["state"] == "not_requested"
        assert service.status()[source]["history"] == []


@pytest.mark.parametrize("source", ["nvd", "epss"])
@pytest.mark.parametrize("timing", ["response", "after_commit"])
@pytest.mark.parametrize("code", [200, 503])
def test_cleanup_contention_preserves_primary_api_result(enriched_api, monkeypatch, source, timing, code):
    client, cisa, service = enriched_api
    fetch_source(service, source)
    old = service.get(CVE)[source]
    cisa.clock = lambda: NOW + timedelta(seconds=7)
    service.commit_timeout = 0.02
    original_store = service._store
    with closing(sqlite3.connect(cisa.db_path, timeout=0, check_same_thread=False)) as writer:
        def lock():
            writer.execute("BEGIN IMMEDIATE")
        def handler(request):
            if timing == "response":
                lock()
            return httpx.Response(code, json=source_document(source, newer=True))
        def store(*args, **kwargs):
            result = original_store(*args, **kwargs)
            if timing == "after_commit":
                lock()
            return result
        service.client.transport = httpx.MockTransport(handler)
        monkeypatch.setattr(service, "_store", store)
        path = "/api/intelligence/nvd/" + CVE + "?refresh=true" if source == "nvd" else "/api/intelligence/epss"
        response = client.post(path, headers=HEADERS)
        succeeded = timing == "after_commit" and code == 200
        assert response.status_code == (200 if succeeded else 502), response.text
        body = response.json()
        report = body if succeeded else body["detail"]["attempt"]
        assert report["cleanup_deferred"] is True
        assert "lease" in report["cleanup_warning"].lower() and "expire" in report["cleanup_warning"].lower()
        current = service.get(CVE)[source]
        if timing == "response":
            assert "id" not in report
            assert "Failure journal not persisted" in report["error"]
            assert current == old  # Not falsely marked unavailable without a durable journal.
        else:
            attempt = current["last_attempt"]
            assert attempt["id"] == (report["last_attempt"]["id"] if succeeded and source == "nvd" else report["id"])
            assert "cleanup_deferred" not in attempt  # Cleanup warning is response-only.
            if succeeded:
                assert current["state"] == "available"
            else:
                assert current["state"] == "unavailable" and current["data"] == old["data"]
                assert "503" in report["error"]
        assert service.status()[source]["busy"] is True
        writer.rollback()
    # No background cleanup/retry is needed for recovery; the original lease expires.
    cisa.clock = lambda: NOW + timedelta(seconds=127)
    assert service.status()[source]["busy"] is False
    monkeypatch.setattr(service, "_store", original_store)
    service.client.transport = httpx.MockTransport(lambda request: httpx.Response(200, json=source_document(source, newer=True)))
    fetch_source(service, source)
    assert service.get(CVE)[source]["state"] == "available"
    assert not service.status()[source]["busy"]


@pytest.mark.parametrize("source", ["nvd", "epss"])
def test_cleanup_contention_does_not_swallow_unrelated_primary_error(intelligence, monkeypatch, source):
    service, cisa = intelligence
    service.commit_timeout = 0.02
    primary = RuntimeError("unrelated primary programming failure")
    with closing(sqlite3.connect(cisa.db_path, timeout=0)) as writer:
        def handler(request):
            writer.execute("BEGIN IMMEDIATE")
            return httpx.Response(200, json=source_document(source))
        def finish(*args):
            raise primary
        service.client.transport = httpx.MockTransport(handler)
        monkeypatch.setattr(service, "_finish", finish)
        with pytest.raises(RuntimeError) as raised:
            fetch_source(service, source)
        assert raised.value is primary
        writer.rollback()


def test_unrelated_cleanup_sqlite_error_is_not_treated_as_contention(intelligence, monkeypatch):
    from contextlib import contextmanager
    service, cisa = intelligence
    @contextmanager
    def broken_connection(*args, **kwargs):
        raise sqlite3.OperationalError("no such table: intelligence_control")
        yield
    monkeypatch.setattr(cisa, "connect", broken_connection)
    with pytest.raises(sqlite3.OperationalError, match="no such table"):
        service._release("nvd", "some-token")
