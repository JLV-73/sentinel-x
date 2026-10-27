"""Synthetic, offline intelligence client contract tests."""
from copy import deepcopy
from datetime import datetime, timezone
import json

import httpx
import pytest

NOW = datetime(2026, 10, 26, 12, tzinfo=timezone.utc)
CVE = "CVE-2026-1234"


def nvd_document(cve=CVE, scores=True):
    metrics = {}
    if scores:
        for version in ("4.0", "3.1", "3.0", "2.0"):
            metrics["cvssMetricV" + ("2" if version == "2.0" else version.replace(".", ""))] = [
                {"source": "cna@example.org", "type": "Primary", "cvssData": {
                    "version": version, "baseScore": 0, "baseSeverity": "NONE", "vectorString": "CVSS:" + version}},
                {"source": "nvd@nist.gov", "type": "Secondary", "cvssData": {
                    "version": version, "baseScore": 9.8, "baseSeverity": "CRITICAL"}}]
    return {"resultsPerPage": 1, "startIndex": 0, "totalResults": 1,
            "format": "NVD_CVE", "version": "2.0", "timestamp": "2026-10-26T10:00:00.000",
            "vulnerabilities": [{"cve": {"id": cve, "published": "2026-01-01T00:00:00.000",
                "lastModified": "2026-10-25T01:02:03.000", "vulnStatus": "Analyzed",
                "descriptions": [{"lang": "en", "value": "Official English."}], "metrics": metrics,
                "weaknesses": [{"source": "cna@example.org", "type": "Primary", "description": [{"lang": "en", "value": "CWE-79"}]}],
                "references": [{"url": "https://example.org/advisory", "source": "cna@example.org", "tags": ["Vendor Advisory"]}],
                "configurations": [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:example:widget:*:*:*:*:*:*:*:*", "matchCriteriaId": "test"}]}]}]}}]}


def test_nvd_preserves_every_metric_source_and_official_fields():
    from app.sourceclients import parse_nvd
    original = nvd_document()
    result = parse_nvd(json.dumps(original).encode(), CVE, NOW)
    official = original["vulnerabilities"][0]["cve"]
    assert result["id"] == CVE
    assert len(result["cvss"]) == 8
    assert {m["version"] for m in result["cvss"]} == {"4.0", "3.1", "3.0", "2.0"}
    assert result["cvss"][0]["base_score"] == 0
    assert {m["source"] for m in result["cvss"]} == {"cna@example.org", "nvd@nist.gov"}
    assert all(m["record_modified"] == official["lastModified"] + "Z" for m in result["cvss"])
    assert result["published"].endswith("Z") and result["last_modified"].endswith("Z")
    assert set(result) == {"id", "published", "last_modified", "vuln_status", "descriptions", "cvss", "weaknesses", "references", "configurations"}
    for name in ("descriptions", "weaknesses", "references", "configurations"):
        assert result[name] == official[name]
    assert parse_nvd(json.dumps(nvd_document(scores=False)).encode(), CVE, NOW)["cvss"] == []
    empty = nvd_document()
    empty.update(totalResults=0, resultsPerPage=0, vulnerabilities=[])
    assert parse_nvd(json.dumps(empty).encode(), CVE, NOW) is None


@pytest.mark.parametrize("field,value", [("id", CVE + "\n"), ("id", "CVE-2026-9999"),
    ("published", "2026-02-30T00:00:00.000"), ("lastModified", "2020-01-01T00:00:00.000"),
    ("descriptions", {}), ("metrics", []), ("references", ["bad"]), ("configurations", [False])])
def test_nvd_invalid_official_fields_rejected(field, value):
    from app.sourceclients import parse_nvd
    doc = nvd_document()
    doc["vulnerabilities"][0]["cve"][field] = value
    with pytest.raises(ValueError):
        parse_nvd(json.dumps(doc).encode(), CVE, NOW)


@pytest.mark.parametrize("field,value", [("baseScore", True), ("baseScore", 10.1),
    ("baseScore", -1), ("baseScore", "9.8"), ("baseScore", float("nan")), ("version", "3.1"), ("baseSeverity", 5)])
def test_nvd_metric_validation(field, value):
    from app.sourceclients import parse_nvd
    doc = nvd_document()
    doc["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV40"][0]["cvssData"][field] = value
    with pytest.raises(ValueError):
        parse_nvd(json.dumps(doc).encode(), CVE, NOW)


@pytest.mark.parametrize("raw", [b'{"x":1,"x":2}', b'{"x":NaN}', b'not JSON', b'[]'])
def test_nvd_invalid_json(raw):
    from app.sourceclients import parse_nvd
    with pytest.raises(ValueError):
        parse_nvd(raw, CVE, NOW)


def epss_document(ids=(CVE,), **changes):
    doc = {"status": "OK", "status-code": 200, "version": "1.0", "access": "public",
           "total": len(ids), "offset": 0, "limit": 100,
           "data": [{"cve": value, "epss": "0.000000000", "percentile": "1.000000000", "date": "2026-10-25"} for value in ids]}
    doc.update(changes)
    return doc


def test_epss_validated_zero_absence_and_official_numeric_strings():
    from app.sourceclients import parse_epss, pack_epss
    parsed = parse_epss(json.dumps(epss_document()).encode(), [CVE, "CVE-2026-2222"], NOW)
    assert parsed == {CVE: {"cve": CVE, "epss": 0.0, "percentile": 1.0, "date": "2026-10-25"}, "CVE-2026-2222": None}
    assert parse_epss(json.dumps(epss_document(())).encode(), [CVE], NOW) == {CVE: None}
    ids = ["CVE-2026-" + str(1000000000000000000 + i) for i in range(201)]
    batches = pack_epss(ids + ids)
    assert [v for batch in batches for v in batch] == ids
    assert all(len(batch) <= 100 and len(",".join(batch)) <= 1800 for batch in batches)


@pytest.mark.parametrize("field,value", [("cve", CVE + "\n"), ("cve", "CVE-2026-9999"),
    ("epss", True), ("epss", "NaN"), ("epss", "Infinity"), ("epss", "1.00001"),
    ("epss", -0.01), ("epss", " 0.5"), ("percentile", None), ("date", "2026-02-30"),
    ("date", "2026-10-27"), ("date", "20261025")])
def test_epss_rejects_invalid_rows(field, value):
    from app.sourceclients import parse_epss
    doc = epss_document()
    doc["data"][0][field] = value
    with pytest.raises(ValueError):
        parse_epss(json.dumps(doc).encode(), [CVE], NOW)


@pytest.mark.parametrize("changes", [{"total": 2}, {"offset": 1}, {"total": True},
    {"status": "ERROR"}, {"version": "2.0"}, {"data": {}}, {"limit": 0}, {"status-code": "200"}])
def test_epss_rejects_invalid_envelope(changes):
    from app.sourceclients import parse_epss
    with pytest.raises(ValueError):
        parse_epss(json.dumps(epss_document(**changes)).encode(), [CVE], NOW)


def test_epss_duplicate_cves_rejected():
    from app.sourceclients import parse_epss
    with pytest.raises(ValueError):
        parse_epss(json.dumps(epss_document((CVE, CVE))).encode(), [CVE], NOW)


def test_fixed_client_secure_bounded_offline_transport(monkeypatch):
    from app.sourceclients import SourceClient
    seen, options = [], []
    original = httpx.Client
    def spy(**kwargs):
        options.append(kwargs)
        return original(**kwargs)
    monkeypatch.setattr(httpx, "Client", spy)
    client = SourceClient()
    client.transport = httpx.MockTransport(lambda req: seen.append(req) or httpx.Response(200, json=nvd_document()))
    fetched = client.request("nvd", [CVE])
    assert fetched.status_code == 200
    assert str(seen[0].url) == "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + CVE
    assert options[0]["verify"] is True and options[0]["trust_env"] is False
    assert options[0]["follow_redirects"] is False
    assert "apiKey" not in seen[0].headers
    client.request("epss", [CVE])
    assert seen[1].url.params["limit"] == "1"
    assert seen[1].url.params["cve"] == CVE
    with pytest.raises(ValueError):
        client.request("arbitrary", [CVE])
    with pytest.raises(ValueError):
        client.request("nvd", [CVE + "\n"])
