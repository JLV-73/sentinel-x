"""Synthetic offline GHSA contracts; no real advisory or live HTTP."""
import json
import hashlib
import httpx
from datetime import timedelta
from pathlib import Path
import pytest
from test_backend import api, NOW, HEADERS, vulnerability

CVE = "CVE-2026-1234"
PATH = "/api/intelligence/ghsa/" + CVE

@pytest.fixture
def ghsa_api(api):
    client, cisa = api
    with cisa.connect() as db:
        db.execute("INSERT INTO vulnerabilities VALUES (?,?)", (CVE, json.dumps(vulnerability())))
    return client, cisa

def snapshot(cisa):
    with cisa.connect(snapshot=True) as db:
        return {table: [tuple(row) for row in db.execute("SELECT * FROM " + table)]
                for table in ("vulnerabilities", "imports", "intelligence_control", "intelligence_cache", "intelligence_attempts", "intelligence_targets")}

def advisory(**changes):
    # Entirely synthetic redistributable fixture; no source advisory is copied.
    path = Path(__file__).parent / "fixtures" / "ghsa-reviewed.synthetic.json"
    result = json.loads(path.read_text(encoding="utf-8"))[0]
    result.update(changes)
    return result


def test_positive_manual_post_preserves_original_and_raw(ghsa_api):
    client, cisa = ghsa_api
    ghsa = client.app.state.ghsa
    calls = []
    record = advisory()
    raw = json.dumps([record]).encode()
    def handle(request):
        calls.append(request)
        assert str(request.url) == "https://api.github.com/advisories?cve_id=" + CVE + "&type=reviewed&per_page=100"
        assert request.headers["x-github-api-version"] == "2022-11-28"
        assert request.headers["accept"] == "application/vnd.github+json"
        assert "authorization" not in request.headers
        return httpx.Response(200, content=raw)
    ghsa.client.transport = httpx.MockTransport(handle)
    response = client.post(PATH, headers=HEADERS)
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["ghsa"]["state"] == "available"
    assert result["ghsa"]["data"] == {"date": record["updated_at"], "advisories": [record]}
    provenance = result["ghsa"]["provenance"]
    assert provenance["sha256"] == hashlib.sha256(raw).hexdigest()
    assert (cisa.db_path.parent / provenance["raw_file"]).read_bytes() == raw
    assert provenance["source"] == "ghsa"
    assert provenance["attribution"] == result["control"]["attribution"]
    assert client.get(PATH).json() == result
    assert client.post(PATH, headers=HEADERS).json() == result
    assert len(calls) == 1


@pytest.mark.parametrize("headers,query,body,code", [
    ({}, "", b"", 403), ({"Origin": HEADERS["Origin"]}, "", b"", 403),
    ({**HEADERS, "Origin": "http://evil.invalid"}, "", b"", 403),
    ({**HEADERS, "Host": "evil.invalid"}, "", b"", 400),
    ([("Origin", HEADERS["Origin"]), ("Origin", HEADERS["Origin"]), ("X-Sentinel-Request", "sync")], "", b"", 403),
    ([("Origin", HEADERS["Origin"]), ("X-Sentinel-Request", "sync"), ("X-Sentinel-Request", "sync")], "", b"", 403),
    (HEADERS, "?url=https://evil.invalid", b"", 422), (HEADERS, "", b"{}", 422),
    (HEADERS, "?refresh=1", b"", 422), (HEADERS, "?refresh=True", b"", 422),
    (HEADERS, "?refresh=true&refresh=false", b"", 422), (HEADERS, "?refresh=", b"", 422)])
def test_manual_guards_prevent_network_and_rows(ghsa_api, headers, query, body, code):
    client, cisa = ghsa_api
    calls = []
    client.app.state.ghsa.client.transport = httpx.MockTransport(lambda req: calls.append(req) or httpx.Response(200, json=[]))
    before = snapshot(cisa)
    response = client.post(PATH + query, headers=headers, content=body)
    assert response.status_code == code, response.text
    assert calls == []
    assert snapshot(cisa) == before


@pytest.mark.parametrize("change", [
    {"cve_id": "CVE-2026-9999"}, {"type": "unreviewed"}, {"ghsa_id": "GHSA-bad"},
    {"updated_at": "2026-99-01T12:00:00Z"}, {"withdrawn_at": "not-a-date"},
    {"updated_at": "2027-01-01T00:00:00Z"}, {"severity": 10},
    {"identifiers": [{"type": "CVE", "value": "CVE-2026-9999"}]},
    {"vulnerabilities": [{"package": {"name": "x", "ecosystem": "pip"}, "vulnerable_version_range": 123, "first_patched_version": None}]},
    {"cvss_severities": {"cvss_v4": {"vector_string": None, "score": 11}}}])
def test_foreign_unreviewed_and_malformed_records_fail_closed(ghsa_api, change):
    client, cisa = ghsa_api
    client.app.state.ghsa.client.transport = httpx.MockTransport(lambda req: httpx.Response(200, json=[advisory(**change)]))
    result = client.post(PATH, headers=HEADERS)
    assert result.status_code == 502, result.text
    cached = result.json()["detail"]["cached"]["ghsa"]
    assert cached["state"] == "unavailable" and cached["last_success"] is None
    assert cached["last_attempt"]["failed"] == 1
    with cisa.connect() as db:
        assert db.execute("SELECT count(*) FROM intelligence_cache WHERE source='ghsa'").fetchone()[0] == 0


def test_next_page_is_failure_not_truncated_absence(ghsa_api):
    client, cisa = ghsa_api
    ghsa = client.app.state.ghsa
    ghsa.client.transport = httpx.MockTransport(lambda req: httpx.Response(200, json=[advisory()]))
    first = client.post(PATH, headers=HEADERS).json()["ghsa"]
    cisa.clock = lambda: NOW + timedelta(seconds=65)
    calls = []
    ghsa.client.transport = httpx.MockTransport(lambda req: calls.append(req) or httpx.Response(200, json=[],
        headers={"Link": '<https://api.github.com/advisories?page=2>; rel="next", <https://api.github.com/advisories?page=2>; rel="last"'}))
    failed = client.post(PATH + "?refresh=true", headers=HEADERS)
    assert failed.status_code == 502, failed.text
    cached = failed.json()["detail"]["cached"]["ghsa"]
    assert cached["data"] == first["data"] and cached["provenance"] == first["provenance"]
    assert cached["retained_after_error"] and cached["state"] == "unavailable"
    assert len(calls) == 1


@pytest.mark.parametrize("status,headers,delay", [
    (403, {"Retry-After": "180"}, 180), (429, {"Retry-After": "Mon, 26 Oct 2026 12:03:00 GMT"}, 180),
    (429, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(int(NOW.timestamp()) + 240)}, 240),
    (200, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(int(NOW.timestamp()) + 300)}, 300)])
def test_source_quota_headers_defer_persistently(ghsa_api, status, headers, delay):
    from app.ghsa import GhsaService
    from app.intelligence import IntelligenceBusy
    client, cisa = ghsa_api
    ghsa = client.app.state.ghsa
    calls = []
    def handle(req):
        calls.append(req)
        # Separate connection proves reservation committed BEFORE HTTP starts.
        with cisa.connect() as db:
            row = db.execute("SELECT next_request,token FROM intelligence_control WHERE source='ghsa'").fetchone()
            assert row[0] == NOW.timestamp() + 65 and row[1]
        return httpx.Response(status, json=[], headers=headers)
    ghsa.client.transport = httpx.MockTransport(handle)
    first = client.post(PATH, headers=HEADERS)
    assert first.status_code == (200 if status == 200 else 502), first.text
    result = client.get(PATH).json()
    assert result["control"]["next_request_at"] == (NOW + timedelta(seconds=delay)).isoformat()
    cisa.clock = lambda: NOW + timedelta(seconds=delay - 1)
    restarted = GhsaService(cisa)
    restarted.client.transport = httpx.MockTransport(lambda req: pytest.fail("Persisted cooldown bypassed"))
    with pytest.raises(IntelligenceBusy):
        restarted.fetch(CVE, refresh=True)
    assert len(calls) == 1


@pytest.mark.parametrize("failure", ["http", "malformed", "transport"])
@pytest.mark.parametrize("empty", [False, True])
def test_success_and_absence_survive_failure_and_staleness(ghsa_api, failure, empty):
    client, cisa = ghsa_api
    ghsa = client.app.state.ghsa
    ghsa.client.transport = httpx.MockTransport(lambda req: httpx.Response(200, json=[] if empty else [advisory()]))
    first = client.post(PATH + "?refresh=false", headers=HEADERS).json()["ghsa"]
    assert first["state"] == ("absent" if empty else "available")
    cisa.clock = lambda: NOW + timedelta(hours=24)
    calls = []
    def handle(req):
        calls.append(req)
        if failure == "transport":
            raise httpx.ReadTimeout("synthetic timeout")
        return httpx.Response(503, content=b"unavailable") if failure == "http" else httpx.Response(200, content=b"[{bad]")
    ghsa.client.transport = httpx.MockTransport(handle)
    assert client.get(PATH).json()["ghsa"]["state"] == "stale"
    before = snapshot(cisa)
    assert client.post(PATH, headers=HEADERS).status_code == 200  # stale cached hit, no automatic refresh
    assert calls == [] and snapshot(cisa) == before
    failed = client.post(PATH + "?refresh=true", headers=HEADERS)
    assert failed.status_code == 502, failed.text
    detail = failed.json()["detail"]
    assert set(detail) == {"error", "attempt", "cached"}
    cached = detail["cached"]["ghsa"]
    assert cached["state"] == "unavailable" and cached["retained_after_error"] and cached["stale"]
    for field in ("data", "provenance", "last_success", "collected_at", "source_date"):
        assert cached[field] == first[field]
    assert client.get(PATH).json() == detail["cached"]
    assert len(calls) == 1


def test_multiple_withdrawn_ranges_nulls_dates_and_zero_unchanged(ghsa_api):
    client, cisa = ghsa_api
    first = advisory(withdrawn_at="2026-10-23T12:00:00Z")
    second = advisory(ghsa_id="GHSA-jmpq-rvwx-2345", html_url="https://github.com/advisories/GHSA-jmpq-rvwx-2345",
        updated_at="2026-10-25T00:00:00+00:00",
        identifiers=[{"type": "CVE", "value": CVE}, {"type": "GHSA", "value": "GHSA-jmpq-rvwx-2345"}])
    second["vulnerabilities"].append({"package": {"ecosystem": "npm", "name": "synthetic-package"},
        "vulnerable_version_range": ">= 0, < 2", "first_patched_version": "2.0.0"})
    client.app.state.ghsa.client.transport = httpx.MockTransport(lambda req: httpx.Response(200, json=[second, first]))
    result = client.post(PATH, headers=HEADERS)
    assert result.status_code == 200, result.text
    data = result.json()["ghsa"]["data"]
    assert data == {"date": second["updated_at"], "advisories": [second, first]}
    assert data["advisories"][0]["cvss_severities"]["cvss_v4"] == {"score": 0.0, "vector_string": None}


@pytest.mark.parametrize("value,code", [("CVE-2026-9999", 404), (CVE + "%0A", 422), ("cve-2026-1234", 422), ("CVE-٢٠٢٦-1234", 422)])
def test_exact_known_local_cve_checked_before_any_io(ghsa_api, value, code):
    client, cisa = ghsa_api
    client.app.state.ghsa.client.transport = httpx.MockTransport(lambda req: pytest.fail("Non-local CVE sent to source"))
    before = snapshot(cisa)
    for method in (client.get, client.post):
        assert method("/api/intelligence/ghsa/" + value, headers=HEADERS).status_code == code
    assert snapshot(cisa) == before


@pytest.mark.parametrize("raw", [b"{}", b"null", b"[NaN]", b"[Infinity]", b"[1e9999]", b'[{"x":1,"x":2}]', b'[],"extra":1', b"[]garbage", b"[", b"[1]"])
def test_strict_json_array_rejects_invalid_or_injected_documents(ghsa_api, raw):
    client, _ = ghsa_api
    client.app.state.ghsa.client.transport = httpx.MockTransport(lambda req: httpx.Response(200, content=raw))
    response = client.post(PATH, headers=HEADERS)
    assert response.status_code == 502, response.text
    assert response.json()["detail"]["cached"]["ghsa"]["last_success"] is None


def test_shared_sixty_five_second_reservation_and_busy_lease(ghsa_api):
    from app.ghsa import GhsaService
    from app.intelligence import IntelligenceBusy
    client, cisa = ghsa_api
    ghsa = client.app.state.ghsa
    calls = []
    def handle(req):
        calls.append(req)
        second = GhsaService(cisa)
        with pytest.raises(IntelligenceBusy):
            second.fetch(CVE, refresh=True)
        return httpx.Response(200, json=[])
    ghsa.client.transport = httpx.MockTransport(handle)
    assert client.post(PATH, headers=HEADERS).status_code == 200
    cisa.clock = lambda: NOW + timedelta(seconds=64)
    assert client.post(PATH + "?refresh=true", headers=HEADERS).status_code == 409
    cisa.clock = lambda: NOW + timedelta(seconds=65)
    assert client.post(PATH + "?refresh=true", headers=HEADERS).status_code == 200
    assert len(calls) == 2


def test_legacy_rows_and_stable_contracts_are_not_modified(ghsa_api):
    from test_intelligence_clients import nvd_document, epss_document
    client, cisa = ghsa_api
    intelligence = client.app.state.intelligence
    intelligence.client.transport = httpx.MockTransport(lambda req: httpx.Response(200,
        json=nvd_document() if req.url.host == "services.nvd.nist.gov" else epss_document()))
    assert client.post("/api/intelligence/nvd/" + CVE, headers=HEADERS).status_code == 200
    assert client.post("/api/intelligence/epss", headers=HEADERS).status_code == 200
    before = snapshot(cisa)
    paths = ("/api/health", "/api/summary", "/api/intelligence/" + CVE, "/api/intelligence/summary", "/api/intelligence/status")
    responses = {path: client.get(path).json() for path in paths}
    client.app.state.ghsa.client.transport = httpx.MockTransport(lambda req: httpx.Response(200, json=[]))
    assert client.post(PATH, headers=HEADERS).status_code == 200
    after = snapshot(cisa)
    for table, rows in before.items():
        if table in ("vulnerabilities", "imports"):
            assert after[table] == rows
        else:
            source_index = 0 if table in ("intelligence_cache", "intelligence_control") else 1
            assert [row for row in after[table] if row[source_index] != "ghsa"] == rows
    assert {path: client.get(path).json() for path in paths} == responses


def test_first_collection_db_lock_is_conflict_without_source_call(ghsa_api):
    client, cisa = ghsa_api
    client.app.state.ghsa.commit_timeout = 0
    client.app.state.ghsa.client.transport = httpx.MockTransport(lambda req: pytest.fail("Locked DB reached source"))
    before = snapshot(cisa)
    with cisa.connect() as writer:
        writer.execute("BEGIN IMMEDIATE")
        response = client.post(PATH, headers=HEADERS)
        assert response.status_code == 409, response.text
    assert snapshot(cisa) == before


@pytest.mark.parametrize("header", [{"Retry-After": "9" * 400},
    {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "9" * 400}])
def test_long_official_cooldown_remains_readable_and_blocks_manual_retry(ghsa_api, header):
    client, cisa = ghsa_api
    client.app.state.ghsa.client.transport = httpx.MockTransport(lambda req: httpx.Response(429, headers=header, json=[]))
    response = client.post(PATH, headers=HEADERS)
    assert response.status_code == 502, response.text
    assert client.get(PATH).status_code == 200
    assert "deferred manual retry" in client.get(PATH).json()["control"]["next_request_at"]
    assert client.post(PATH, headers=HEADERS).status_code == 409


def test_storage_rejection_retains_previous_cache_and_journals_failure(ghsa_api):
    client, cisa = ghsa_api
    ghsa = client.app.state.ghsa
    ghsa.client.transport = httpx.MockTransport(lambda req: httpx.Response(200, json=[advisory()]))
    first = client.post(PATH, headers=HEADERS).json()["ghsa"]
    cisa.clock = lambda: NOW + timedelta(seconds=65)
    with cisa.connect() as db:
        db.executescript("CREATE TRIGGER reject_ghsa_cache BEFORE UPDATE ON intelligence_cache WHEN NEW.source='ghsa' BEGIN SELECT RAISE(ABORT,'synthetic storage failure'); END;")
    failed = client.post(PATH + "?refresh=true", headers=HEADERS)
    assert failed.status_code == 502, failed.text
    detail = failed.json()["detail"]
    assert "Storage commit failed" in detail["error"]
    cached = detail["cached"]["ghsa"]
    assert cached["data"] == first["data"] and cached["last_success"] == first["last_success"]
    assert cached["last_attempt"]["status"] == "failed" and cached["retained_after_error"]
    with cisa.connect() as db:
        assert db.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        assert db.execute("SELECT count(*) FROM intelligence_attempts WHERE source='ghsa'").fetchone()[0] == 2


@pytest.mark.parametrize("phase", ["headers", "chunk", "eof"])
def test_cooperative_deadline_checks_after_headers_chunks_and_eof(phase):
    from app.ghsa_client import GhsaClient
    clock = [0.0]
    class Stream(httpx.SyncByteStream):
        def __iter__(self):
            if phase == "chunk":
                clock[0] = 46
            yield b"[]"
            if phase == "eof":
                clock[0] = 46
    def handle(req):
        if phase == "headers":
            clock[0] = 46
        return httpx.Response(200, stream=Stream())
    client = GhsaClient()
    client.monotonic = lambda: clock[0]
    client.transport = httpx.MockTransport(handle)
    with pytest.raises(ValueError, match="budget"):
        client.request(CVE)


@pytest.mark.parametrize("phase", ["headers", "chunk", "encoding"])
def test_source_byte_and_encoding_bounds(phase):
    from app.ghsa_client import GhsaClient
    class Stream(httpx.SyncByteStream):
        def __iter__(self):
            yield b"["
            yield b"   ]"
    client = GhsaClient()
    client.max_bytes = 4
    headers = {"content-length": "5"} if phase == "headers" else {"content-encoding": "gzip"} if phase == "encoding" else {}
    client.transport = httpx.MockTransport(lambda req: httpx.Response(200, headers=headers, stream=Stream()))
    with pytest.raises(ValueError, match="size limit|Content-Encoding"):
        client.request(CVE)


@pytest.mark.parametrize("status", [301, 302, 307, 308])
def test_redirect_is_not_followed(ghsa_api, status):
    client, _ = ghsa_api
    calls = []
    client.app.state.ghsa.client.transport = httpx.MockTransport(lambda req: calls.append(req) or httpx.Response(status,
        headers={"location": "https://evil.invalid"}))
    assert client.post(PATH, headers=HEADERS).status_code == 502
    assert len(calls) == 1 and calls[0].url.host == "api.github.com"


def test_rate_headers_persist_even_when_response_body_fails(ghsa_api):
    client, cisa = ghsa_api
    ghsa = client.app.state.ghsa
    ghsa.client.max_bytes = 1
    ghsa.client.transport = httpx.MockTransport(lambda req: httpx.Response(429, content=b"too big",
        headers={"Retry-After": "240", "X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(int(NOW.timestamp()) + 360)}))
    assert client.post(PATH, headers=HEADERS).status_code == 502
    assert client.get(PATH).json()["control"]["next_request_at"] == (NOW + timedelta(seconds=360)).isoformat()


def test_maximum_page_and_duplicate_advisories():
    from app.ghsa_client import parse_ghsa
    entries = []
    alphabet = "23456789cfghjmpqrvwx"
    for index in range(100):
        identifier = "GHSA-2345-6789-22" + alphabet[index // len(alphabet)] + alphabet[index % len(alphabet)]
        record = advisory(ghsa_id=identifier, html_url="https://github.com/advisories/" + identifier,
            identifiers=[{"type": "CVE", "value": CVE}, {"type": "GHSA", "value": identifier}])
        entries.append(record)
    assert len(parse_ghsa(json.dumps(entries).encode(), CVE, NOW)["advisories"]) == 100
    with pytest.raises(ValueError, match="one-page limit"):
        parse_ghsa(json.dumps(entries + [advisory()]).encode(), CVE, NOW)
    with pytest.raises(ValueError, match="Duplicate GHSA"):
        parse_ghsa(json.dumps([entries[0], entries[0]]).encode(), CVE, NOW)


def test_ambient_tokens_never_become_authorization(ghsa_api, monkeypatch):
    client, _ = ghsa_api
    for name in ("GITHUB_TOKEN", "GH_TOKEN", "GITHUB_API_KEY"):
        monkeypatch.setenv(name, "synthetic-not-a-credential")
    calls = []
    client.app.state.ghsa.client.transport = httpx.MockTransport(lambda req: calls.append(req) or httpx.Response(200, json=[]))
    assert client.post(PATH, headers=HEADERS).status_code == 200
    assert len(calls) == 1 and "authorization" not in calls[0].headers


def test_embedded_source_epss_remains_raw_and_separate(ghsa_api):
    client, _ = ghsa_api
    client.app.state.ghsa.client.transport = httpx.MockTransport(lambda req: httpx.Response(200, json=[advisory()]))
    result = client.post(PATH, headers=HEADERS)
    assert result.status_code == 200
    assert result.json()["ghsa"]["data"]["advisories"][0]["epss"] == advisory()["epss"]
    assert client.get("/api/intelligence/" + CVE).json()["epss"]["state"] == "not_requested"


def test_nullable_updated_date_preserves_original_and_null_source_date(ghsa_api):
    client, _ = ghsa_api
    record = advisory(updated_at=None)
    client.app.state.ghsa.client.transport = httpx.MockTransport(lambda req: httpx.Response(200, json=[record]))
    response = client.post(PATH, headers=HEADERS)
    assert response.status_code == 200, response.text
    assert response.json()["ghsa"]["data"] == {"date": None, "advisories": [record]}
    assert response.json()["ghsa"]["source_date"] is None


def test_commit_failure_rolls_back_success_and_retains_prior_data(ghsa_api, monkeypatch):
    from contextlib import contextmanager
    import sqlite3
    client, cisa = ghsa_api
    ghsa = client.app.state.ghsa
    ghsa.client.transport = httpx.MockTransport(lambda req: httpx.Response(200, json=[advisory()]))
    first = client.post(PATH, headers=HEADERS).json()["ghsa"]
    cisa.clock = lambda: NOW + timedelta(seconds=65)
    connect = cisa.connect
    failed = [False]
    class Connection:
        def __init__(self, db):
            self.db = db
        def __getattr__(self, name):
            return getattr(self.db, name)
        def commit(self):
            if not failed[0]:
                failed[0] = True
                raise sqlite3.OperationalError("synthetic commit failure")
            return self.db.commit()
    @contextmanager
    def fail_commit_once(*args, **kwargs):
        with connect(*args, **kwargs) as db:
            yield Connection(db)
    monkeypatch.setattr(cisa, "connect", fail_commit_once)
    response = client.post(PATH + "?refresh=true", headers=HEADERS)
    assert response.status_code == 502, response.text
    detail = response.json()["detail"]
    assert "synthetic commit failure" in detail["error"]
    assert detail["cached"]["ghsa"]["last_success"] == first["last_success"]
    assert detail["cached"]["ghsa"]["data"] == first["data"]
    assert client.get(PATH).json() == detail["cached"]
    with connect() as db:
        statuses = [row[0] for row in db.execute("SELECT status FROM intelligence_attempts WHERE source='ghsa' ORDER BY id")]
        assert statuses == ["success", "failed"]


def test_local_get_is_additive_read_only_and_lazy(ghsa_api):
    client, cisa = ghsa_api
    before = snapshot(cisa)
    response = client.get(PATH)
    assert response.status_code == 200, response.text
    result = response.json()
    assert set(result) == {"cve_id", "ghsa", "control"}
    assert result["cve_id"] == CVE
    assert result["ghsa"]["state"] == "not_requested"
    assert result["control"] == {"next_request_at": None, "freshness_hours": 24,
        "minimum_interval_seconds": 65, "max_advisories": 100,
        "attribution": {"name": "GitHub Advisory Database", "url": "https://github.com/advisories",
                        "license": "CC-BY-4.0", "license_url": "https://creativecommons.org/licenses/by/4.0/"}}
    assert client.get(PATH).json() == result
    assert snapshot(cisa) == before
    assert not (cisa.db_path.parent / "intelligence_raw").exists()
    assert {r[0] for r in before["intelligence_control"]} == {"nvd", "epss"}
