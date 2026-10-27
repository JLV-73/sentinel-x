"""Offline contract tests. Fixtures are synthetic and never enter production data."""
from pathlib import Path
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json

import httpx
import pytest
from fastapi.testclient import TestClient

HEADERS = {"Origin": "http://127.0.0.1:5177", "X-Sentinel-Request": "sync"}
NOW = datetime(2026, 10, 26, 12, tzinfo=timezone.utc)


def vulnerability(cve="CVE-2026-1234", **changes):
    item = {"cveID": cve, "vendorProject": "Example", "product": "Widget",
            "vulnerabilityName": "Example vulnerability", "dateAdded": "2026-10-20",
            "shortDescription": "Example description", "requiredAction": "Apply updates",
            "dueDate": "2026-11-10", "knownRansomwareCampaignUse": "Known",
            "notes": "", "cwes": ["CWE-79"], "forensicTriage": "Yes",
            "futureOfficialField": {"preserve": True}}
    item.update(changes)
    return item


def catalog(*items):
    return {"catalogVersion": "2026.10.26", "dateReleased": "2026-10-26T10:00:00.000Z",
            "count": len(items), "vulnerabilities": list(items)}


@pytest.fixture
def api(tmp_path):
    from app.main import create_app
    app = create_app(db_path=tmp_path / "sentinel.db")
    with TestClient(app, base_url="http://127.0.0.1:8007") as client:
        app.state.service.clock = lambda: NOW
        yield client, app.state.service


def source(service, body):
    raw = body if isinstance(body, bytes) else json.dumps(body).encode()
    service.transport = httpx.MockTransport(lambda request: httpx.Response(200, content=raw))
    return raw


def test_valid_sync_keeps_official_fields_and_hashed_raw_snapshot(api):
    client, service = api
    item = vulnerability()
    raw = source(service, catalog(item))
    response = client.post("/api/sync", headers=HEADERS)
    assert response.status_code == 200, response.text
    imported = response.json()
    assert imported["status"] == "success"
    assert imported["record_count"] == 1
    assert imported["sha256"] == hashlib.sha256(raw).hexdigest()
    assert imported["source_url"] == imported["source_canonical"]
    assert imported["catalog_version"] == "2026.10.26"
    assert imported["schema_sha256"] == "0d5865c98694c5bfba2c78a26caf814f406b3fce8bfb81bef79e99c7f288b0e7"
    assert (service.db_path.parent / "source" / (imported["sha256"] + ".json")).read_bytes() == raw
    assert client.get("/api/vulnerabilities/CVE-2026-1234").json() == {
        "vulnerability": item, "provenance": imported}
    assert client.get("/api/health").json()["data_mode"] == "REAL DATA"


def invalid_documents():
    good = catalog(vulnerability())
    cases = []
    for key, value in [("count", 2), ("dateReleased", "2026-02-30T10:00:00Z"),
                       ("dateReleased", "2099-01-01T00:00:00Z"), ("count", -1)]:
        bad = deepcopy(good)
        bad[key] = value
        cases.append(bad)
    bad = deepcopy(good)
    bad["vulnerabilities"].append(deepcopy(bad["vulnerabilities"][0]))
    bad["count"] = 2
    cases.append(bad)
    for key, value in [("dateAdded", "2026-02-30"), ("dateAdded", "2026-10-27"),
                       ("dateAdded", "2026-11-11"), ("dueDate", "2026-10-19"),
                       ("dueDate", "not-a-date"), ("cveID", "CVE-WRONG"), ("cwes", ["bad"])]:
        bad = deepcopy(good)
        bad["vulnerabilities"][0][key] = value
        cases.append(bad)
    bad = deepcopy(good)
    del bad["vulnerabilities"][0]["requiredAction"]
    cases.append(bad)
    cases.extend([b'{"count":0,"count":1}', b'{"x":NaN}', b'<html>failure</html>'])
    return cases


@pytest.mark.parametrize("document", invalid_documents())
def test_invalid_catalog_is_journaled_without_importing(api, document):
    client, service = api
    source(service, document)
    response = client.post("/api/sync", headers=HEADERS)
    assert response.status_code == 502, response.text
    assert response.json()["detail"]["status"] == "failed"
    assert response.json()["detail"]["error"]
    status = client.get("/api/sync/status").json()
    assert status["last_attempt"]["status"] == "failed"
    assert status["last_success"] is None
    assert status["database"] == {"status": "ok", "integrity": "ok", "count": 0}
    assert status["history"] == [status["last_attempt"]]
    assert status["data_mode"] == "NO DATA"
    assert status["syncing"] is False


@pytest.mark.parametrize("failure", ["403", "timeout", "invalid", "redirect", "length", "stream"])
def test_only_official_fallback_is_used_after_rejected_canonical(api, failure, monkeypatch):
    from app.service import CANONICAL, FALLBACK
    client, service = api
    monkeypatch.setattr(service, "max_bytes", 2048, raising=False)
    seen = []

    class Chunks(httpx.SyncByteStream):
        def __iter__(self):
            yield b"x" * 1024
            yield b"x" * 1025

    def handler(request):
        seen.append(str(request.url))
        assert 0 < request.extensions["timeout"]["read"] <= 20
        if len(seen) == 1:
            if failure == "timeout":
                raise httpx.ReadTimeout("simulated timeout")
            if failure == "redirect":
                return httpx.Response(302, headers={"location": "https://attacker.invalid/feed"})
            if failure == "length":
                return httpx.Response(200, headers={"content-length": "999999999"}, content=b"{}");
            if failure == "stream":
                return httpx.Response(200, stream=Chunks())
            return httpx.Response(403 if failure == "403" else 200, content=b"invalid")
        return httpx.Response(200, json=catalog(vulnerability()))

    service.transport = httpx.MockTransport(handler)
    response = client.post("/api/sync", headers=HEADERS)
    assert response.status_code == 200, response.text
    assert seen == [CANONICAL, FALLBACK]
    record = response.json()
    assert record["source_canonical"] == CANONICAL
    assert record["source_url"] == FALLBACK
    assert [a["status"] for a in record["download_attempts"]] == ["failed", "success"]
    assert record["download_attempts"][0]["error"]


@pytest.mark.parametrize("headers,query,body,expected", [
    ({}, "", b"", 403),
    ({"Origin": HEADERS["Origin"]}, "", b"", 403),
    ({"X-Sentinel-Request": "sync"}, "", b"", 403),
    ({**HEADERS, "Origin": "http://evil.invalid"}, "", b"", 403),
    ({**HEADERS, "Origin": "null"}, "", b"", 403),
    ({**HEADERS, "X-Sentinel-Request": "wrong"}, "", b"", 403),
    ({**HEADERS, "Host": "evil.invalid"}, "", b"", 400),
    (HEADERS, "?source=https://evil.invalid", b"", 422),
    (HEADERS, "", b'{"source":"https://evil.invalid"}', 422),
])
def test_sync_security_rejects_before_network_or_journal(api, headers, query, body, expected):
    client, service = api
    calls = []
    service.transport = httpx.MockTransport(lambda req: calls.append(req) or httpx.Response(200, json=catalog(vulnerability())))
    response = client.post("/api/sync" + query, headers=headers, content=body)
    assert response.status_code == expected
    assert calls == []
    assert client.get("/api/sync/status").json()["history"] == []


def test_success_cooldown_blocks_network_until_60_seconds_and_survives_restart(api):
    from datetime import timedelta
    from app.main import create_app
    client, service = api
    calls = []
    service.transport = httpx.MockTransport(lambda req: calls.append(req) or httpx.Response(200, json=catalog(vulnerability())))
    assert client.post("/api/sync", headers=HEADERS).status_code == 200
    assert client.post("/api/sync", headers=HEADERS).status_code == 409
    service.clock = lambda: NOW + timedelta(seconds=59.999)
    assert client.post("/api/sync", headers=HEADERS).status_code == 409
    replacement = create_app(db_path=service.db_path)
    with TestClient(replacement, base_url="http://127.0.0.1:8007") as other:
        replacement.state.service.clock = lambda: NOW + timedelta(seconds=59)
        replacement.state.service.transport = service.transport
        assert other.post("/api/sync", headers=HEADERS).status_code == 409
    assert len(calls) == 1
    assert len(client.get("/api/sync/status").json()["history"]) == 1
    service.clock = lambda: NOW + timedelta(seconds=60)
    assert client.post("/api/sync", headers=HEADERS).status_code == 200
    assert len(calls) == 2


def test_concurrent_sync_is_rejected_while_reads_remain_responsive(api):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    from app.main import create_app
    client, service = api
    started, release = Event(), Event()
    calls = []

    def handler(request):
        calls.append(request)
        started.set()
        assert release.wait(5), "test did not release source response"
        return httpx.Response(200, json=catalog(vulnerability()))

    other_app = create_app(db_path=service.db_path)
    with TestClient(other_app, base_url="http://127.0.0.1:8007") as other, ThreadPoolExecutor(max_workers=1) as pool:
        other_app.state.service.clock = lambda: NOW
        service.transport = other_app.state.service.transport = httpx.MockTransport(handler)
        work = pool.submit(client.post, "/api/sync", headers=HEADERS)
        try:
            assert started.wait(3)
            assert client.get("/api/sync/status").json()["syncing"] is True
            assert client.get("/api/health").status_code == 200
            assert other.post("/api/sync", headers=HEADERS).status_code == 409
            assert len(calls) == 1
        finally:
            release.set()
        assert work.result(timeout=5).status_code == 200
    assert client.get("/api/sync/status").json()["syncing"] is False


def test_fresh_database_health_reports_no_data(tmp_path):
    try:
        from app.main import create_app
    except ImportError:
        create_app = None
    assert callable(create_app), "create_app is not implemented"
    from fastapi.testclient import TestClient
    with TestClient(create_app(db_path=tmp_path / "sentinel.db"), base_url="http://127.0.0.1:8007") as client:
        assert client.get("/api/health").json() == {
            "status": "ok", "database": "ok", "data_mode": "NO DATA"
        }
        assert (tmp_path / "sentinel.db").is_file()
