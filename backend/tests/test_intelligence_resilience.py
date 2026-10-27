"""Offline fault injection, consistent snapshots, concurrency and rate safety."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from copy import deepcopy
from datetime import timedelta
from threading import Event
import json

import httpx
import pytest

from app.intelligence import IntelligenceService, IntelligenceBusy, IntelligenceFailure
from app.sourceclients import SourceClient, parse_nvd, parse_epss
from test_backend import NOW, HEADERS, vulnerability
from test_intelligence_clients import CVE, nvd_document, epss_document
from test_intelligence_storage import intelligence
from test_intelligence_api import enriched_api
from test_backend import api


def test_nvd_real_metric_names_secondary_v2_severity_ssvc_and_unknown_cvss():
    doc = nvd_document()
    metrics = doc["vulnerabilities"][0]["cve"]["metrics"]
    metrics["ssvcV203"] = [{"source": "cisa", "ssvcData": {"decision": "Act"}}]
    metrics["cvssMetricV41"] = [{"source": "future@example.org", "cvssData": {"version": "4.1", "baseScore": 7.7}}]
    v2 = metrics["cvssMetricV2"][0]
    v2["baseSeverity"] = "HIGH"
    del v2["cvssData"]["baseSeverity"]
    result = parse_nvd(json.dumps(doc).encode(), CVE, NOW)
    assert len(result["cvss"]) == 9
    assert next(v for v in result["cvss"] if v["version"] == "2.0")["base_severity"] == "HIGH"
    assert result["cvss"][-1]["version"] == "4.1"


@pytest.mark.parametrize("config", [{"nodes": False}, {"nodes": [{"operator": "XOR"}]},
    {"nodes": [{"negate": "false"}]}, {"nodes": [{"cpeMatch": [{"vulnerable": "yes", "criteria": 4}]}]}])
def test_nvd_nested_configuration_types_rejected(config):
    doc = nvd_document(scores=False)
    doc["vulnerabilities"][0]["cve"]["configurations"] = [config]
    with pytest.raises(ValueError):
        parse_nvd(json.dumps(doc).encode(), CVE, NOW)


@pytest.mark.parametrize("changes", [{"version": "1.0"}, {"totalResults": True}, {"totalResults": 2}, {"resultsPerPage": 2}, {"startIndex": 1}, {"timestamp": "2026-02-30T00:00:00"}])
def test_nvd_invalid_envelopes(changes):
    doc = nvd_document()
    doc.update(changes)
    with pytest.raises(ValueError):
        parse_nvd(json.dumps(doc).encode(), CVE, NOW)


@pytest.mark.parametrize("kind", ["headers", "chunks", "end", "size", "length", "timeout"])
def test_bounded_stream_deadlines_and_errors(kind):
    client, elapsed, consumed, closed = SourceClient(), [0], [], []
    client.monotonic = lambda: elapsed[0]
    client.max_bytes = 10
    class Stream(httpx.SyncByteStream):
        def __iter__(self):
            if kind == "headers":
                pytest.fail("Expired headers must be rejected before reading")
            if kind == "end":
                elapsed[0] = 46
                return
            for _ in range(30):
                if kind == "timeout":
                    raise httpx.ReadTimeout("offline timeout")
                elapsed[0] += 10 if kind == "chunks" else 0
                consumed.append(1)
                yield b"x"
        def close(self):
            closed.append(True)
    def handler(req):
        if kind == "headers":
            elapsed[0] = 46
        assert 0 < req.extensions["timeout"]["read"] <= 20
        return httpx.Response(200, stream=Stream(), headers={"content-length": "11"} if kind == "length" else {})
    client.transport = httpx.MockTransport(handler)
    with pytest.raises((ValueError, httpx.ReadTimeout)):
        client.request("nvd", [CVE])
    assert closed == [True]
    if kind == "chunks":
        assert len(consumed) == 5  # No 64KiB accumulation before deadline check.


def test_concurrent_source_rejected_without_holding_cisa_writer_lock(intelligence):
    service, cisa = intelligence
    other = IntelligenceService(cisa)
    other.initialize()
    started, release = Event(), Event()
    calls = []
    def handler(req):
        calls.append(req)
        started.set()
        assert release.wait(5)
        return httpx.Response(200, json=nvd_document())
    service.client.transport = httpx.MockTransport(handler)
    other.client.transport = service.client.transport
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(service.fetch_nvd, CVE)
        try:
            assert started.wait(3)
            assert other.status()["nvd"]["busy"]
            assert cisa.health()["database"] == "ok"
            # Unlike a network-long BEGIN IMMEDIATE, this permits CISA writes.
            with cisa.connect(timeout=0) as db:
                db.execute("BEGIN IMMEDIATE")
                db.execute("INSERT INTO vulnerabilities VALUES (?,?)", ("CVE-2026-9999", json.dumps(vulnerability("CVE-2026-9999"))))
            with pytest.raises(IntelligenceBusy):
                other.fetch_nvd(CVE, refresh=True)
        finally:
            release.set()
        assert pending.result(timeout=5)["state"] == "available"
    assert len(calls) == 1 and not service.status()["nvd"]["busy"]
    coverage = service.summary()["nvd"]
    assert coverage["available"] == 1 and coverage["not_requested"] == 1


def test_failed_cache_write_rolls_back_success_and_journals_failure(intelligence):
    service, cisa = intelligence
    old = service.fetch_nvd(CVE)
    cisa.clock = lambda: NOW + timedelta(seconds=7)
    with cisa.connect() as db:
        db.execute("CREATE TRIGGER reject_intelligence BEFORE INSERT ON intelligence_cache BEGIN SELECT RAISE(ABORT, 'offline cache write failure'); END")
    with pytest.raises(IntelligenceFailure) as failed:
        service.fetch_nvd(CVE, refresh=True)
    assert "Storage commit failed" in failed.value.attempt["error"]
    cached = service.get(CVE)["nvd"]
    assert cached["last_success"] == old["last_success"] and cached["data"] == old["data"]
    assert cached["state"] == "unavailable" and cached["retained_after_error"]
    assert len(service.status()["nvd"]["history"]) == 2
    with cisa.connect() as db:
        assert db.execute("SELECT count(*) FROM intelligence_attempts WHERE status='success'").fetchone()[0] == 1


@pytest.mark.parametrize("code", [302, 403, 500, 503])
def test_http_failures_never_become_absence_or_follow_redirect(enriched_api, code):
    client, _, intelligence = enriched_api
    calls = []
    intelligence.client.transport = httpx.MockTransport(lambda req: calls.append(req) or httpx.Response(code, headers={"location": "https://evil.invalid"}, content=b"source error"))
    response = client.post("/api/intelligence/nvd/" + CVE, headers=HEADERS)
    assert response.status_code == 502 and len(calls) == 1
    cached = client.get("/api/intelligence/" + CVE).json()["nvd"]
    assert cached["state"] == "unavailable" and cached["data"] is None
    assert cached["last_attempt"]["absent"] == 0 and len(cached["last_attempt"]["provenances"]) == 1


def test_request_rate_reserved_at_actual_start_after_client_setup(intelligence, monkeypatch):
    service, cisa = intelligence
    from app import sourceclients
    original = httpx.Client
    seconds, setups, calls = [0], [], []
    def client(**kwargs):
        if not setups:
            seconds[0] += 4  # Simulate initial TLS context/client construction.
            cisa.clock = lambda: NOW + timedelta(seconds=seconds[0])
        setups.append(True)
        return original(**kwargs)
    monkeypatch.setattr(sourceclients.httpx, "Client", client)
    service.client.transport = httpx.MockTransport(lambda req: calls.append(seconds[0]) or httpx.Response(200, json=nvd_document()))
    service.fetch_nvd(CVE)
    seconds[0] = 7
    with pytest.raises(IntelligenceBusy):
        service.fetch_nvd(CVE, refresh=True)
    seconds[0] = 11
    service.fetch_nvd(CVE, refresh=True)
    assert calls == [4, 11]


@pytest.mark.parametrize("raw", [b'{"x":1,"x":2}', b'{"unknown":1e999}', b'{"x":NaN}', b'[]', b'bad JSON'])
def test_both_parsers_reject_invalid_json_everywhere(raw):
    for parser, ids in ((parse_nvd, CVE), (parse_epss, [CVE])):
        with pytest.raises(ValueError):
            parser(raw, ids, NOW)


def test_retry_after_is_enforced_even_when_raw_storage_fails(intelligence, monkeypatch):
    service, cisa = intelligence
    service.client.transport = httpx.MockTransport(lambda req: httpx.Response(429, headers={"Retry-After": "3600"}))
    def no_disk(*args):
        raise OSError("offline raw storage unavailable")
    monkeypatch.setattr(service, "_raw", no_disk)
    with pytest.raises(IntelligenceFailure):
        service.fetch_nvd(CVE)
    cisa.clock = lambda: NOW + timedelta(seconds=100)
    with pytest.raises(IntelligenceBusy):
        service.fetch_nvd(CVE, refresh=True)


def test_expired_setup_does_not_start_network(monkeypatch):
    client, elapsed, calls = SourceClient(), [0], []
    client.monotonic = lambda: elapsed[0]
    original = httpx.Client
    def slow_setup(**kwargs):
        elapsed[0] = 46
        return original(**kwargs)
    monkeypatch.setattr(httpx, "Client", slow_setup)
    client.transport = httpx.MockTransport(lambda req: calls.append(req) or httpx.Response(200))
    with pytest.raises(ValueError, match="time budget"):
        client.request("nvd", [CVE])
    assert calls == []


@pytest.mark.parametrize("source", ["nvd", "epss"])
def test_retry_after_headers_survive_body_timeout(intelligence, source):
    service, cisa = intelligence
    calls = []
    class Timeout(httpx.SyncByteStream):
        def __iter__(self):
            raise httpx.ReadTimeout("offline response body timeout")
            yield b""
    service.client.transport = httpx.MockTransport(lambda req: calls.append(req) or httpx.Response(429, headers={"Retry-After": "3600"}, stream=Timeout()))
    fetch = (lambda: service.fetch_nvd(CVE, refresh=True)) if source == "nvd" else service.fetch_epss
    with pytest.raises(IntelligenceFailure):
        fetch()
    cisa.clock = lambda: NOW + timedelta(seconds=100)
    with pytest.raises(IntelligenceBusy):
        fetch()
    assert len(calls) == 1


def test_blocked_commit_is_rolled_back_then_failed_journal_is_persisted(intelligence, monkeypatch):
    import sqlite3
    from contextlib import closing
    service, cisa = intelligence
    first = service.fetch_nvd(CVE)
    cisa.clock = lambda: NOW + timedelta(seconds=7)
    service.commit_timeout = 0.05
    original_journal = service._journal
    with closing(sqlite3.connect(cisa.db_path)) as reader:
        def handler(req):
            reader.execute("BEGIN")
            reader.execute("SELECT * FROM intelligence_cache").fetchall()
            return httpx.Response(200, json=nvd_document(scores=False))
        service.client.transport = httpx.MockTransport(handler)
        def journal(db, record):
            if record["status"] == "failed":
                reader.rollback()
            return original_journal(db, record)
        monkeypatch.setattr(service, "_journal", journal)
        with pytest.raises(IntelligenceFailure) as failed:
            service.fetch_nvd(CVE, refresh=True)
        assert "locked" in failed.value.attempt["error"]
    cached = service.get(CVE)["nvd"]
    assert cached["data"] == first["data"] and cached["last_success"] == first["last_success"]
    assert cached["last_attempt"]["status"] == "failed" and cached["state"] == "unavailable"


def test_expired_worker_lease_recovers_without_background_activity(intelligence):
    service, cisa = intelligence
    token = service._acquire("nvd")
    replacement = IntelligenceService(cisa)
    replacement.client.transport = httpx.MockTransport(lambda req: httpx.Response(200, json=nvd_document()))
    cisa.clock = lambda: NOW + timedelta(seconds=119)
    with pytest.raises(IntelligenceBusy):
        replacement.fetch_nvd(CVE)
    cisa.clock = lambda: NOW + timedelta(seconds=120)
    assert replacement.fetch_nvd(CVE)["state"] == "available"
    service._release("nvd", token)
    assert not replacement.status()["nvd"]["busy"]


def test_nvd_rolling_rate_and_http_date_retry_after(intelligence):
    from email.utils import format_datetime
    service, cisa = intelligence
    seconds, calls = [0], []
    cisa.clock = lambda: NOW + timedelta(seconds=seconds[0])
    service.client.transport = httpx.MockTransport(lambda req: calls.append(seconds[0]) or httpx.Response(200, json=nvd_document()))
    for second in (0, 7, 14, 21, 28, 35):
        seconds[0] = second
        service.fetch_nvd(CVE, refresh=True)
        if second < 35:
            seconds[0] = second + 6.999
            with pytest.raises(IntelligenceBusy):
                service.fetch_nvd(CVE, refresh=True)
    assert calls == [0, 7, 14, 21, 28, 35]
    assert all(sum(start - 30 < other <= start for other in calls) <= 5 for start in calls)
    seconds[0] = 42
    until = format_datetime(NOW + timedelta(seconds=342), usegmt=True)
    service.client.transport = httpx.MockTransport(lambda req: httpx.Response(429, headers={"Retry-After": until}))
    with pytest.raises(IntelligenceFailure):
        service.fetch_nvd(CVE, refresh=True)
    seconds[0] = 341.999
    with pytest.raises(IntelligenceBusy):
        service.fetch_nvd(CVE, refresh=True)


def test_extreme_retry_after_defers_safely_without_500_or_short_clamp(intelligence):
    service, cisa = intelligence
    service.client.transport = httpx.MockTransport(lambda req: httpx.Response(429, headers={"Retry-After": "9" * 400}))
    with pytest.raises(IntelligenceFailure):
        service.fetch_nvd(CVE)
    cisa.clock = lambda: NOW + timedelta(days=365)
    with pytest.raises(IntelligenceBusy, match="cooldown"):
        service.fetch_nvd(CVE, refresh=True)


def test_failure_journal_impossibility_is_reported_not_fabricated(intelligence):
    service, cisa = intelligence
    with cisa.connect() as db:
        db.execute("CREATE TRIGGER reject_journal BEFORE INSERT ON intelligence_attempts BEGIN SELECT RAISE(ABORT, 'offline storage unavailable'); END")
    with pytest.raises(IntelligenceFailure) as failed:
        service.fetch_nvd(CVE)
    assert "Failure journal not persisted" in failed.value.attempt["error"]
    assert "id" not in failed.value.attempt
    assert service.get(CVE)["nvd"]["state"] == "not_requested"
    assert service.status()["nvd"]["history"] == []


def test_nonfinite_unknown_json_fields_are_also_rejected():
    doc = nvd_document()
    raw = json.dumps(doc).encode()[:-1] + b',"extra":1e999}'
    with pytest.raises(ValueError, match="Nonfinite"):
        parse_nvd(raw, CVE, NOW)


def test_huge_numeric_score_is_validation_failure_not_overflow():
    doc = nvd_document()
    doc["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV40"][0]["cvssData"]["baseScore"] = 10 ** 500
    with pytest.raises(ValueError):
        parse_nvd(json.dumps(doc).encode(), CVE, NOW)


def test_score_date_stale_even_when_collected_now_and_zero_is_scored(intelligence):
    service, _ = intelligence
    doc = epss_document()
    doc["data"][0]["date"] = "2026-10-23"
    service.client.transport = httpx.MockTransport(lambda req: httpx.Response(200, json=doc))
    service.fetch_epss()
    cached = service.get(CVE)["epss"]
    assert cached["state"] == "stale" and cached["stale"]
    assert cached["data"]["epss"] == 0
    assert service.summary()["epss"]["with_scores"] == 1


@pytest.mark.parametrize("endpoint", ["get", "summary", "status"])
def test_intelligence_data_and_attempts_use_same_snapshot(intelligence, monkeypatch, endpoint):
    service, cisa = intelligence
    old = service.fetch_nvd(CVE)
    with cisa.connect() as db:
        assert db.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
    other = IntelligenceService(cisa)
    cisa.clock = lambda: NOW + timedelta(seconds=7)
    other.client.transport = httpx.MockTransport(lambda req: httpx.Response(200, json=nvd_document(scores=False)))
    original, refreshed = cisa.connect, []
    class Interleaved:
        def __init__(self, db): self.db = db
        def execute(self, sql, *args):
            if sql.startswith("SELECT attempt_id,succeeded FROM intelligence_targets") and not refreshed:
                refreshed.append(other.fetch_nvd(CVE, refresh=True))
            return self.db.execute(sql, *args)
        def __getattr__(self, name): return getattr(self.db, name)
    @contextmanager
    def connect(*args, **kwargs):
        with original(*args, **kwargs) as db:
            yield Interleaved(db)
    # The writer must retain the original connect, not recurse through the hook.
    from app.service import Service
    writer_cisa = Service(cisa.db_path)
    writer_cisa.clock = cisa.clock
    other.cisa = writer_cisa
    monkeypatch.setattr(cisa, "connect", connect)
    result = service.get(CVE) if endpoint == "get" else getattr(service, endpoint)()
    assert refreshed and refreshed[0]["data"]["cvss"] == []
    if endpoint == "get":
        assert result["nvd"]["data"] == old["data"] and result["nvd"]["last_success"] == old["last_success"]
    else:
        assert result["nvd"]["with_scores"] == 1
    assert service.summary()["nvd"]["with_scores"] == 0
