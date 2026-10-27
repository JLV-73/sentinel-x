"""P1 routes are additive, read-only on GET and guarded before any source call."""
from datetime import timedelta
import json
import httpx
import pytest

from test_backend import api, HEADERS, NOW, vulnerability
from test_intelligence_clients import CVE, nvd_document, epss_document


@pytest.fixture
def enriched_api(api):
    client, cisa = api
    with cisa.connect() as db:
        db.execute("INSERT INTO vulnerabilities VALUES (?,?)", (CVE, json.dumps(vulnerability())))
    intelligence = client.app.state.intelligence
    def handler(req):
        return httpx.Response(200, json=nvd_document() if req.url.host == "services.nvd.nist.gov" else epss_document())
    intelligence.client.transport = httpx.MockTransport(handler)
    return client, cisa, intelligence


def test_gets_never_fetch_and_exact_contract_shapes(enriched_api):
    client, cisa, intelligence = enriched_api
    intelligence.client.transport = httpx.MockTransport(lambda req: pytest.fail("GET/startup must never collect"))
    old = {path: client.get(path).json() for path in ("/api/health", "/api/summary", "/api/vulnerabilities", "/api/vulnerabilities/" + CVE, "/api/sync/status")}
    item = client.get("/api/intelligence/" + CVE).json()
    assert set(item) == {"cve_id", "nvd", "epss"}
    assert set(item["nvd"]) == {"state", "stale", "retained_after_error", "collected_at", "source_date", "data", "provenance", "last_attempt", "last_success"}
    assert item["nvd"]["state"] == item["epss"]["state"] == "not_requested"
    assert client.get("/api/intelligence", params={"cve": CVE}).json() == {"items": {CVE: item}}
    coverage = {"available": 0, "with_scores": 0, "absent": 0, "unavailable": 0, "stale": 0, "not_requested": 1}
    assert client.get("/api/intelligence/summary").json() == {"catalog_total": 1, "nvd": coverage, "epss": coverage}
    status = client.get("/api/intelligence/status").json()
    assert set(status) == {"nvd", "epss"}
    assert set(status["nvd"]) == {"source", *coverage, "last_attempt", "last_success", "history", "freshness_hours", "busy", "endpoint"}
    assert status["nvd"]["freshness_hours"] == 168 and status["epss"]["freshness_hours"] == 24
    assert old == {path: client.get(path).json() for path in old}


def test_protected_manual_nvd_cache_first_refresh_and_epss_routes(enriched_api):
    client, cisa, intelligence = enriched_api
    assert client.post("/api/intelligence/nvd/" + CVE, headers=HEADERS).json()["state"] == "available"
    assert client.post("/api/intelligence/nvd/" + CVE, headers=HEADERS).status_code == 200
    assert client.post("/api/intelligence/nvd/" + CVE + "?refresh=true", headers=HEADERS).status_code == 409
    cisa.clock = lambda: NOW + timedelta(seconds=7)
    assert client.post("/api/intelligence/nvd/" + CVE + "?refresh=true", headers=HEADERS).status_code == 200
    result = client.post("/api/intelligence/epss", headers=HEADERS)
    assert result.status_code == 200, result.text
    assert set(result.json()) == {"id", "source", "status", "started_at", "finished_at", "requested", "available", "absent", "failed", "error", "provenances"}
    assert result.json()["available"] == 1
    assert client.get("/api/intelligence/" + CVE).json()["epss"]["data"]["epss"] == 0
    assert client.get("/api/intelligence/summary").json()["nvd"]["with_scores"] == 1


@pytest.mark.parametrize("path", ["/api/intelligence/nvd/" + CVE, "/api/intelligence/epss"])
@pytest.mark.parametrize("headers,query,body,code", [({}, "", b"", 403),
    ({"Origin": HEADERS["Origin"]}, "", b"", 403),
    ({**HEADERS, "Origin": "http://evil.invalid"}, "", b"", 403),
    ({**HEADERS, "Host": "evil.invalid"}, "", b"", 400),
    (HEADERS, "?url=https://evil.invalid", b"", 422),
    (HEADERS, "", b'{}', 422),
    ([("Origin", HEADERS["Origin"]), ("Origin", HEADERS["Origin"]), ("X-Sentinel-Request", "sync")], "", b"", 403)])
def test_new_post_guards_reject_before_collection(enriched_api, path, headers, query, body, code):
    client, cisa, intelligence = enriched_api
    intelligence.client.transport = httpx.MockTransport(lambda req: pytest.fail("Rejected request reached source"))
    assert client.post(path + query, headers=headers, content=body).status_code == code
    assert client.get("/api/intelligence/status").json()["nvd"]["history"] == []
    assert client.get("/api/intelligence/status").json()["epss"]["history"] == []


@pytest.mark.parametrize("query", ["", "?cve=", "?cve=CVE-2026-1234%0A", "?cve=CVE-٢٠٢٦-1234", "?cve=" + CVE + "," + CVE,
    "?cve=" + CVE + "&cve=" + CVE, "?cve=" + ",".join("CVE-2026-" + str(1000+i) for i in range(101)), "?cve=" + "x" * 3001])
def test_collection_query_strict_bounds(enriched_api, query):
    assert enriched_api[0].get("/api/intelligence" + query).status_code == 422


@pytest.mark.parametrize("path", ["/api/intelligence/CVE-2026-9999", "/api/intelligence?cve=CVE-2026-9999"])
def test_read_unknown_local_cve_is_404(enriched_api, path):
    assert enriched_api[0].get(path).status_code == 404


def test_nvd_unknown_malformed_and_query_types(enriched_api):
    client, _, intelligence = enriched_api
    intelligence.client.transport = httpx.MockTransport(lambda req: pytest.fail("Rejected request reached source"))
    assert client.post("/api/intelligence/nvd/CVE-2026-9999", headers=HEADERS).status_code == 404
    assert client.post("/api/intelligence/nvd/" + CVE + "%0A", headers=HEADERS).status_code == 422
    assert client.post("/api/intelligence/nvd/" + CVE + "?refresh=1", headers=HEADERS).status_code == 422
    assert client.post("/api/intelligence/nvd/" + CVE + "?refresh=true&refresh=false", headers=HEADERS).status_code == 422
    assert client.post("/api/intelligence/epss?refresh=true", headers=HEADERS).status_code == 422


def test_failed_source_api_returns_502_with_retained_data(enriched_api):
    client, cisa, intelligence = enriched_api
    first = client.post("/api/intelligence/nvd/" + CVE, headers=HEADERS).json()
    cisa.clock = lambda: NOW + timedelta(seconds=7)
    intelligence.client.transport = httpx.MockTransport(lambda req: httpx.Response(500))
    failed = client.post("/api/intelligence/nvd/" + CVE + "?refresh=true", headers=HEADERS)
    assert failed.status_code == 502
    assert failed.json()["detail"]["attempt"]["status"] == "failed"
    assert failed.json()["detail"]["cached"]["data"] == first["data"]
    assert failed.json()["detail"]["cached"]["state"] == "unavailable"
    assert client.post("/api/intelligence/epss", headers=HEADERS).status_code == 502
