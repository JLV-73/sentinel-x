"""Offline P1-B endpoint contracts; synthetic fixtures stay in .cache only."""
from datetime import datetime, timedelta, timezone
import json

from fastapi.testclient import TestClient
import pytest

from app.main import create_app
from test_backend import NOW, vulnerability


DEFAULT_FILTERS = {
    "q": "", "added_since": None, "added_until": None,
    "nvd_state": "all", "epss_state": "all", "cvss_availability": "all",
    "cvss_min": None, "epss_min": None, "recent_days": 30,
    "recent_only": False, "sort": "desc", "page": 1, "page_size": 20,
}
SOURCE_FIELDS = {"state", "stale", "retained_after_error", "collected_at",
                 "source_date", "data", "provenance"}


@pytest.fixture
def triage_api(tmp_path):
    app = create_app(db_path=tmp_path / "sentinel.db")
    with TestClient(app, base_url="http://127.0.0.1:8007") as client:
        app.state.service.clock = lambda: NOW
        yield client, app.state.service


def test_empty_endpoint_returns_defaulted_contract(triage_api):
    client, _ = triage_api
    response = client.get("/api/triage")
    assert response.status_code == 200, response.text
    assert response.json() == {
        "data_mode": "NO DATA", "as_of_utc": NOW.isoformat(),
        "catalog_total": 0, "total": 0, "page": 1, "pages": 1,
        "page_size": 20, "filters": DEFAULT_FILTERS,
        "cisa_provenance": None, "items": [],
    }


def seed_kev(cisa, *items, provenance=None):
    with cisa.connect() as db:
        db.executemany("INSERT INTO vulnerabilities VALUES (?,?)",
                       [(item["cveID"], json.dumps(item)) for item in items])
        if provenance is not None:
            db.execute("INSERT INTO imports(status,payload) VALUES ('success',?)", (json.dumps(provenance),))
            db.execute("INSERT INTO imports(status,payload) VALUES ('failed','{}')")


def source_data(source, cve="CVE-2026-1234"):
    from app.sourceclients import parse_nvd, parse_epss
    from test_intelligence_clients import nvd_document, epss_document
    if source == "nvd":
        return parse_nvd(json.dumps(nvd_document(cve)).encode(), cve, NOW)
    return parse_epss(json.dumps(epss_document([cve])).encode(), [cve], NOW)[cve]


def seed_source(cisa, source, cve, data, *, age=timedelta(0), cached=True,
                failed=False, json_null=False):
    collected = (NOW - age).isoformat()
    provenance = {"source": source, "url": "https://example.org/original?cve=" + cve,
                  "sha256": "a" * 64, "collected_at": collected,
                  "raw_file": "intelligence_raw/" + source + "/original.json"}
    with cisa.connect() as db:
        if cached:
            attempt = db.execute("INSERT INTO intelligence_attempts(source,status,payload) VALUES (?,'success',?)",
                                 (source, json.dumps({"source": source, "status": "success", "provenances": [provenance]}))).lastrowid
            db.execute("INSERT INTO intelligence_targets VALUES (?,?,?,1)", (attempt, source, cve))
            source_date = (data["last_modified"] if source == "nvd" else data["date"]) if data else None
            db.execute("INSERT INTO intelligence_cache VALUES (?,?,?,?,?,?,?)",
                       (source, cve, json.dumps(data) if data is not None or json_null else None,
                        json.dumps(provenance), collected, source_date, attempt))
        if failed:
            attempt = db.execute("INSERT INTO intelligence_attempts(source,status,payload) VALUES (?,'failed',?)",
                                 (source, json.dumps({"source": source, "status": "failed"}))).lastrowid
            db.execute("INSERT INTO intelligence_targets VALUES (?,?,?,0)", (attempt, source, cve))
    return provenance


@pytest.mark.parametrize("source", ["nvd", "epss"])
@pytest.mark.parametrize("scenario,state,stale,retained", [
    ("not_requested", "not_requested", False, False),
    ("available", "available", False, False),
    ("absent", "absent", False, False),
    ("json_null", "absent", False, False),
    ("stale", "stale", True, False),
    ("stale_absent", "stale", True, False),
    ("failed_first", "unavailable", False, False),
    ("failed_retained", "unavailable", False, True),
    ("failed_stale", "unavailable", True, True),
    ("failed_absent", "unavailable", False, True),
])
def test_compact_source_states_match_existing_detail(triage_api, source, scenario, state, stale, retained):
    client, cisa = triage_api
    original = vulnerability()
    provenance = {"id": 17, "status": "success", "source_url": "https://www.cisa.gov/original",
                  "sha256": "b" * 64, "schema_sha256": cisa.schema_hash}
    seed_kev(cisa, original, provenance=provenance)
    if scenario != "not_requested":
        data = None if scenario in {"absent", "json_null", "stale_absent", "failed_absent"} else source_data(source)
        seed_source(cisa, source, original["cveID"], data,
                    age=timedelta(hours=168 if source == "nvd" else 24) if "stale" in scenario else timedelta(0),
                    cached=scenario != "failed_first", failed=scenario.startswith("failed"),
                    json_null=scenario == "json_null")
    response = client.get("/api/triage")
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["data_mode"] == "REAL DATA" and result["catalog_total"] == result["total"] == 1
    assert result["cisa_provenance"] == provenance
    assert len(result["items"]) == 1
    item = result["items"][0]
    assert set(item) == {"cve_id", "kev", "nvd", "epss", "indicators"}
    assert item["cve_id"] == original["cveID"] and item["kev"] == original
    view = item[source]
    assert set(view) == SOURCE_FIELDS
    assert (view["state"], view["stale"], view["retained_after_error"]) == (state, stale, retained)
    detail = client.get("/api/intelligence/" + item["cve_id"]).json()
    for name in ("nvd", "epss"):
        assert item[name] == {key: detail[name][key] for key in SOURCE_FIELDS}
    assert item["indicators"] == {
        "recent_kev": True, "cvss_threshold_met": None, "epss_threshold_met": None,
        "nvd_needs_enrichment": item["nvd"]["state"] != "available" or item["nvd"]["stale"],
        "epss_needs_enrichment": item["epss"]["state"] != "available" or item["epss"]["stale"],
    }


@pytest.mark.parametrize("source", ["nvd", "epss"])
@pytest.mark.parametrize("selected,indices", [
    ("all", set(range(9))), ("available", {1}), ("not_requested", {0}),
    ("absent", {2}), ("unavailable", {4, 5, 6, 8}),
    ("stale", {3, 6, 7}), ("needs_attention", {0, 2, 3, 4, 5, 6, 7, 8}),
])
def test_source_state_filters_include_independent_staleness(triage_api, source, selected, indices):
    client, cisa = triage_api
    ids = [f"CVE-2026-{2000 + index}" for index in range(9)]
    seed_kev(cisa, *(vulnerability(value) for value in ids))
    for index in range(1, 9):
        seed_source(cisa, source, ids[index], None if index in {2, 7, 8} else source_data(source, ids[index]),
                    cached=index != 4, failed=index in {4, 5, 6, 8},
                    age=timedelta(days=8) if index in {3, 6, 7} else timedelta(0))
    response = client.get("/api/triage", params={source + "_state": selected})
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["total"] == len(indices)
    assert {item["cve_id"] for item in result["items"]} == {ids[index] for index in indices}
    assert result["filters"] == {**DEFAULT_FILTERS, source + "_state": selected}


@pytest.fixture
def numeric_catalog(triage_api):
    client, cisa = triage_api
    ids = [f"CVE-2026-{3000 + index}" for index in range(7)]
    seed_kev(cisa, *(vulnerability(value) for value in ids))
    originals = {}
    for index in range(1, 7):
        nvd = source_data("nvd", ids[index])
        if index == 1:
            for metric in nvd["cvss"]:
                metric["base_score"] = 0
        if index == 2:
            nvd["cvss"] = []
        if index == 4:
            nvd["cvss"] = [{**nvd["cvss"][0], "base_score": 10}]
        epss = {**source_data("epss", ids[index]),
                "epss": {1: 0.0, 2: 0.0, 3: 0.02, 4: 1.0, 5: 0.7, 6: 0.2}[index],
                "percentile": 0.01 if index == 4 else 0.99}
        if index == 2:
            epss = None
        for source, data in (("nvd", nvd), ("epss", epss)):
            seed_source(cisa, source, ids[index], data, failed=index == 5,
                        age=timedelta(days=8) if index in {5, 6} else timedelta(0))
        originals[ids[index]] = {"nvd": nvd, "epss": epss}
    return client, ids, originals


@pytest.mark.parametrize("params,indices", [
    ({"cvss_availability": "scored"}, {1, 3, 4, 5, 6}),
    ({"cvss_availability": "unscored"}, {0, 2}),
    ({"cvss_availability": "all"}, set(range(7))),
    ({"cvss_min": 0}, {1, 3, 4, 5, 6}),
    ({"cvss_min": 9.8}, {3, 4, 5, 6}),
    ({"cvss_min": 9.9}, {4}),
    ({"epss_min": 0}, {1, 3, 4, 5, 6}),
    ({"epss_min": 0.02}, {3, 4, 5, 6}),
    ({"epss_min": 0.03}, {4, 5, 6}),
    ({"epss_min": 1}, {4}),
    ({"cvss_min": 9.8, "epss_min": 0.5}, {4, 5}),
    ({"cvss_min": 9.8, "nvd_state": "unavailable"}, {5}),
    ({"epss_min": 0.1, "epss_state": "stale"}, {5, 6}),
    ({"cvss_min": 9.8, "epss_min": 0.02, "nvd_state": "available", "epss_state": "available"}, {3, 4}),
    ({"cvss_min": 0, "cvss_availability": "unscored"}, set()),
])
def test_numeric_filters_use_retained_original_values_not_percentile(numeric_catalog, params, indices):
    client, ids, originals = numeric_catalog
    response = client.get("/api/triage", params=params)
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["total"] == len(indices)
    assert {item["cve_id"] for item in result["items"]} == {ids[index] for index in indices}
    assert result["filters"] == {**DEFAULT_FILTERS, **params}
    assert result["catalog_total"] == 7 and result["data_mode"] == "REAL DATA"
    for item in result["items"]:
        if item["cve_id"] in originals:
            assert item["nvd"]["data"] == originals[item["cve_id"]]["nvd"]
            assert item["epss"]["data"] == originals[item["cve_id"]]["epss"]
        assert item["indicators"]["cvss_threshold_met"] is (True if "cvss_min" in params else None)
        assert item["indicators"]["epss_threshold_met"] is (True if "epss_min" in params else None)


@pytest.mark.parametrize("source,age,source_days,stale", [
    ("nvd", timedelta(hours=168) - timedelta(microseconds=1), 1, False),
    ("nvd", timedelta(hours=168), 1, True),
    ("epss", timedelta(hours=24) - timedelta(microseconds=1), 2, False),
    ("epss", timedelta(hours=24), 2, True),
    ("epss", timedelta(0), 3, True),
])
def test_existing_freshness_boundaries_are_preserved(triage_api, source, age, source_days, stale):
    client, cisa = triage_api
    value = "CVE-2026-1234"
    seed_kev(cisa, vulnerability(value))
    data = source_data(source, value)
    if source == "epss":
        data["date"] = (NOW.date() - timedelta(days=source_days)).isoformat()
    seed_source(cisa, source, value, data, age=age)
    item = client.get("/api/triage").json()["items"][0]
    assert item[source]["state"] == ("stale" if stale else "available")
    assert item[source]["stale"] is stale
    assert item["indicators"][source + "_needs_enrichment"] is stale
    assert item[source]["data"] == data


@pytest.mark.parametrize("source", ["nvd", "epss"])
def test_old_cache_can_be_read_without_attempt_or_target_history(triage_api, source):
    client, cisa = triage_api
    value = "CVE-2026-1234"
    seed_kev(cisa, vulnerability(value))
    data = source_data(source, value)
    provenance = seed_source(cisa, source, value, data)
    with cisa.connect() as db:
        db.execute("DELETE FROM intelligence_targets")
        db.execute("DELETE FROM intelligence_attempts")
    view = client.get("/api/triage").json()["items"][0][source]
    assert view["state"] == "available" and not view["retained_after_error"]
    assert view["data"] == data and view["provenance"] == provenance


@pytest.mark.parametrize("values,minimum,expected", [
    ([], None, None), ([0], None, None), ([], 0, None),
    ([0], 0, True), ([0], 0.1, False), ([0, 9.8], 9.8, True),
    ([0, 9.8], 9.9, False), ([0.02], 0.02, True), ([0.02], 0.03, False),
])
def test_threshold_indicator_is_ternary_without_coercing_missing_to_zero(values, minimum, expected):
    from app.triage import threshold_met
    assert threshold_met(values, minimum) is expected
