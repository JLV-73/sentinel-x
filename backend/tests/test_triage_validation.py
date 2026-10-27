"""Fail closed on malformed/ambiguous triage inputs before snapshot reads."""
import pytest

from test_triage import triage_api, DEFAULT_FILTERS


INVALID = [
    {"unexpected": "x"}, {"url": "https://example.org"},
    {"q": "x" * 201}, {"added_since": "2026-02-30"}, {"added_until": "2026-02-29"},
    {"added_since": "2026-1-01"}, {"added_until": "20261026"},
    {"added_since": "2026-W43-1"}, {"added_until": "2026-10-26T00:00:00Z"},
    {"added_since": "٢٠٢٦-10-26"}, {"added_until": "2026-１０-26"},
    {"added_since": "2026-10-26\n"}, {"added_until": " 2026-10-26"},
    {"added_since": "0000-01-01"}, {"added_until": ""},
    {"added_since": "2026-10-26", "added_until": "2026-10-25"},
    {"nvd_state": "fresh"}, {"epss_state": "AVAILABLE"}, {"cvss_availability": "available"},
    {"cvss_min": "-0.1"}, {"cvss_min": "10.01"}, {"cvss_min": "NaN"},
    {"cvss_min": "inf"}, {"cvss_min": "-inf"}, {"cvss_min": "1e999"},
    {"cvss_min": ""}, {"cvss_min": "true"},
    {"epss_min": "-0.001"}, {"epss_min": "1.01"}, {"epss_min": "70"},
    {"epss_min": "NaN"}, {"epss_min": "Infinity"}, {"epss_min": "-Infinity"},
    {"epss_min": "1e999"}, {"epss_min": ""},
    {"recent_days": "0"}, {"recent_days": "3651"}, {"recent_days": "1.5"},
    {"recent_days": "true"}, {"recent_only": "maybe"}, {"recent_only": "2"},
    {"sort": "dateAdded"}, {"sort": "DESC"}, {"page": "0"}, {"page": "-1"},
    {"page": "1.5"}, {"page": "NaN"}, {"page_size": "0"}, {"page_size": "101"},
    {"page_size": "-1"}, {"page_size": "2.5"},
]


@pytest.mark.parametrize("params", INVALID)
def test_invalid_inputs_reject_before_read(triage_api, monkeypatch, params):
    client, _ = triage_api
    import app.triage as triage
    calls = []
    original = triage.listing
    def observed(*args):
        calls.append(args)
        return original(*args)
    monkeypatch.setattr(triage, "listing", observed)
    response = client.get("/api/triage", params=params)
    assert response.status_code == 422, response.text
    assert calls == []


@pytest.mark.parametrize("key,value", [(key, "" if value is None else str(value).lower())
                                       for key, value in DEFAULT_FILTERS.items()])
def test_duplicate_query_fields_always_rejected(triage_api, key, value):
    client, _ = triage_api
    # Optional fields need a valid scalar too: duplicate rejection must not rely
    # on a separate scalar-validation failure.
    value = {"added_since": "2026-01-01", "added_until": "2026-12-31",
             "cvss_min": "0", "epss_min": "0"}.get(key, value)
    assert client.get("/api/triage", params=[(key, value), (key, value)]).status_code == 422


@pytest.mark.parametrize("params,normalized", [
    ({"q": "x" * 200}, {"q": "x" * 200}),
    ({"added_since": "2024-02-29", "added_until": "9999-12-31"},
     {"added_since": "2024-02-29", "added_until": "9999-12-31"}),
    ({"cvss_min": "0", "epss_min": "1e-2"}, {"cvss_min": 0.0, "epss_min": 0.01}),
    ({"cvss_min": "10", "epss_min": "1"}, {"cvss_min": 10.0, "epss_min": 1.0}),
    ({"recent_days": "3650", "recent_only": "false", "page_size": "100", "page": "9999999999"},
     {"recent_days": 3650, "recent_only": False, "page_size": 100, "page": 9999999999}),
])
def test_valid_boundary_inputs_normalized_in_echo(triage_api, params, normalized):
    response = triage_api[0].get("/api/triage", params=params)
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["filters"] == {**DEFAULT_FILTERS, **normalized}
    assert result["items"] == [] and result["pages"] == 1


@pytest.mark.parametrize("hosts", [[("Host", "evil.invalid")],
                                   [("Host", "127.0.0.1:8007"), ("Host", "127.0.0.1:8007")]])
def test_triage_uses_existing_host_guard(triage_api, hosts):
    assert triage_api[0].get("/api/triage", headers=hosts).status_code == 400
