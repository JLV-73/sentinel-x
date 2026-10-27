"""Additive cache/state/provenance tests; temporary SQLite only."""
from datetime import timedelta
import hashlib
import json

import httpx
import pytest

from test_backend import api, NOW, vulnerability
from test_intelligence_clients import CVE, nvd_document


@pytest.fixture
def intelligence(api):
    from app.intelligence import IntelligenceService
    client, cisa = api
    item = vulnerability()
    with cisa.connect() as db:
        db.execute("INSERT INTO vulnerabilities VALUES (?,?)", (CVE, json.dumps(item)))
    service = IntelligenceService(cisa)
    service.initialize()
    service.client.transport = httpx.MockTransport(lambda req: httpx.Response(200, json=nvd_document()))
    return service, cisa


def test_nvd_cache_provenance_staleness_failure_retention_and_recovery(intelligence):
    from app.intelligence import IntelligenceFailure
    service, cisa = intelligence
    assert service.get(CVE)["nvd"]["state"] == "not_requested"
    calls = []
    raw = json.dumps(nvd_document()).encode()
    service.client.transport = httpx.MockTransport(lambda req: calls.append(req) or httpx.Response(200, content=raw))
    value = service.fetch_nvd(CVE)
    assert value["state"] == "available" and not value["stale"]
    assert value["last_attempt"] == value["last_success"]
    assert value["provenance"]["sha256"] == hashlib.sha256(raw).hexdigest()
    assert (cisa.db_path.parent / value["provenance"]["raw_file"]).read_bytes() == raw
    assert service.fetch_nvd(CVE) == value and len(calls) == 1
    cisa.clock = lambda: NOW + timedelta(days=7)
    stale = service.fetch_nvd(CVE)
    assert stale["state"] == "stale" and stale["stale"] and len(calls) == 1
    service.client.transport = httpx.MockTransport(lambda req: httpx.Response(503, content=b"service unavailable"))
    with pytest.raises(IntelligenceFailure) as failure:
        service.fetch_nvd(CVE, refresh=True)
    assert failure.value.attempt["failed"] == 1
    cached = service.get(CVE)["nvd"]
    assert cached["state"] == "unavailable" and cached["retained_after_error"] and cached["stale"]
    assert cached["data"] == value["data"] and cached["provenance"] == value["provenance"]
    assert cached["last_success"] == value["last_success"]
    assert cached["last_attempt"]["status"] == "failed"
    cisa.clock = lambda: NOW + timedelta(days=7, seconds=7)
    service.client.transport = httpx.MockTransport(lambda req: httpx.Response(200, json=nvd_document(scores=False)))
    recovered = service.fetch_nvd(CVE, refresh=True)
    assert recovered["state"] == "available" and recovered["data"]["cvss"] == []
    assert not recovered["retained_after_error"]
    assert service.summary()["nvd"] == {"available": 1, "with_scores": 0, "absent": 0, "unavailable": 0, "stale": 0, "not_requested": 0}


def test_valid_absence_distinguished_from_failed_first_query(intelligence):
    from app.intelligence import IntelligenceFailure
    service, cisa = intelligence
    service.client.transport = httpx.MockTransport(lambda req: httpx.Response(200, content=b'{broken'))
    with pytest.raises(IntelligenceFailure):
        service.fetch_nvd(CVE)
    cached = service.get(CVE)["nvd"]
    assert cached["state"] == "unavailable" and not cached["retained_after_error"]
    assert cached["data"] is None and cached["last_success"] is None
    attempt = cached["last_attempt"]
    assert len(attempt["provenances"]) == 1
    assert (cisa.db_path.parent / attempt["provenances"][0]["raw_file"]).read_bytes() == b'{broken'
    cisa.clock = lambda: NOW + timedelta(seconds=7)
    empty = nvd_document()
    empty.update(vulnerabilities=[], totalResults=0, resultsPerPage=0)
    service.client.transport = httpx.MockTransport(lambda req: httpx.Response(200, json=empty))
    cached = service.fetch_nvd(CVE)
    assert cached["state"] == "absent" and cached["data"] is None
    assert cached["last_success"]["absent"] == 1
    assert service.fetch_nvd(CVE)["state"] == "absent"


def test_rate_rejection_persists_across_instances_and_failures(intelligence):
    from app.intelligence import IntelligenceBusy, IntelligenceFailure, IntelligenceService
    service, cisa = intelligence
    service.fetch_nvd(CVE)
    another = IntelligenceService(cisa)
    another.initialize()
    another.client.transport = httpx.MockTransport(lambda req: httpx.Response(429, headers={"Retry-After": "120"}, content=b"rate limited"))
    with pytest.raises(IntelligenceBusy):
        another.fetch_nvd(CVE, refresh=True)
    assert len(service.status()["nvd"]["history"]) == 1
    cisa.clock = lambda: NOW + timedelta(seconds=7)
    with pytest.raises(IntelligenceFailure):
        another.fetch_nvd(CVE, refresh=True)
    cisa.clock = lambda: NOW + timedelta(seconds=126)
    with pytest.raises(IntelligenceBusy):
        service.fetch_nvd(CVE, refresh=True)
    cisa.clock = lambda: NOW + timedelta(seconds=127)
    assert service.fetch_nvd(CVE, refresh=True)["state"] == "available"


def test_epss_catalogue_batches_partial_retention_and_date_staleness(intelligence):
    from test_intelligence_clients import epss_document
    service, cisa = intelligence
    ids = ["CVE-2026-" + str(1000 + i) for i in range(101)]
    with cisa.connect() as db:
        db.executemany("INSERT OR IGNORE INTO vulnerabilities VALUES (?,?)", [(value, json.dumps(vulnerability(value))) for value in ids])
    elapsed, calls = [0.0], []
    def advance(seconds):
        elapsed[0] += seconds
        cisa.clock = lambda: NOW + timedelta(seconds=elapsed[0])
    service.sleep = advance
    def handler(req):
        requested = req.url.params["cve"].split(",")
        calls.append((elapsed[0], requested))
        return httpx.Response(200, json=epss_document(requested))
    service.client.transport = httpx.MockTransport(handler)
    first = service.fetch_epss()
    assert first["requested"] == 102 and first["available"] == 102 and first["status"] == "success"
    assert len(calls) == 2 and calls[1][0] - calls[0][0] >= 1
    assert all(len(batch) <= 100 and len(",".join(batch)) <= 1800 for _, batch in calls)
    retained_id = calls[-1][1][-1]
    cached = service.get(retained_id)["epss"]
    advance(1)
    calls.clear()
    def partial(req):
        requested = req.url.params["cve"].split(",")
        calls.append((elapsed[0], requested))
        return httpx.Response(200, json=epss_document(requested)) if len(calls) == 1 else httpx.Response(503)
    service.client.transport = httpx.MockTransport(partial)
    result = service.fetch_epss()
    assert result["status"] == "partial" and result["available"] == 100 and result["failed"] == 2
    after = service.get(retained_id)["epss"]
    assert after["state"] == "unavailable" and after["retained_after_error"]
    assert after["data"] == cached["data"] and after["last_success"] == cached["last_success"]
    summary = service.summary()
    assert summary["catalog_total"] == 102 and summary["epss"]["available"] == 100
    assert summary["epss"]["unavailable"] == 2 and summary["epss"]["with_scores"] == 102
    # Collection age and daily score age are independent staleness checks.
    cisa.clock = lambda: NOW + timedelta(hours=24, seconds=elapsed[0])
    assert service.get(CVE)["epss"]["stale"]


def test_epss_long_retry_after_defers_remaining_batches_without_retry(intelligence):
    from app.intelligence import IntelligenceBusy, IntelligenceFailure
    service, cisa = intelligence
    with cisa.connect() as db:
        db.executemany("INSERT OR IGNORE INTO vulnerabilities VALUES (?,?)", [("CVE-2026-" + str(1000 + i), "{}") for i in range(101)])
    calls = []
    service.client.transport = httpx.MockTransport(lambda req: calls.append(req) or httpx.Response(429, headers={"Retry-After": "3600"}))
    service.sleep = lambda seconds: pytest.fail("Must defer manual retry, not sleep through Retry-After")
    with pytest.raises(IntelligenceFailure) as error:
        service.fetch_epss()
    assert error.value.attempt["failed"] == 102 and len(calls) == 1
    assert "defer" in error.value.attempt["error"].lower()
    with pytest.raises(IntelligenceBusy):
        service.fetch_epss()


def test_catalog_required_and_cisa_payload_untouched(intelligence):
    service, cisa = intelligence
    before = (cisa.detail(CVE), cisa.status(), cisa.listing("", "", None, None, "desc", 1, 20))
    service.fetch_nvd(CVE)
    assert before == (cisa.detail(CVE), cisa.status(), cisa.listing("", "", None, None, "desc", 1, 20))
    with pytest.raises(KeyError):
        service.fetch_nvd("CVE-2026-9999")
    with pytest.raises(ValueError):
        service.get(CVE + "\n")
