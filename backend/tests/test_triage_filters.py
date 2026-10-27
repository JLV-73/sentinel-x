"""Literal catalogue criteria, UTC calendar recency, order and pagination."""
from datetime import datetime, timezone, timedelta

import pytest

from test_backend import vulnerability
from test_triage import triage_api, seed_kev, numeric_catalog, DEFAULT_FILTERS


@pytest.fixture
def dated_catalog(triage_api):
    client, cisa = triage_api
    dates = ["2026-09-26", "2026-09-27", "2026-10-25", "2026-10-26", "2026-10-26", "2026-10-27"]
    items = [vulnerability(f"CVE-2026-{4000 + index}", dateAdded=day,
                           vendorProject="%_ O'Reilly" if index == 1 else "Example",
                           product="Unique Widget" if index == 2 else "Gadget")
             for index, day in enumerate(dates)]
    # The UTC day is October 26, not the clock's local October 27.
    cisa.clock = lambda: datetime(2026, 10, 27, 1, tzinfo=timezone(timedelta(hours=2)))
    seed_kev(cisa, *items)
    return client, items


@pytest.mark.parametrize("params,indices", [
    ({}, [5, 4, 3, 2, 1, 0]),
    ({"sort": "asc"}, [0, 1, 2, 3, 4, 5]),
    ({"sort": "asc", "page": 2, "page_size": 2}, [2, 3]),
    ({"page": 2, "page_size": 2}, [3, 2]),
    ({"page": 4, "page_size": 2}, []),
    ({"added_since": "2026-09-27", "added_until": "2026-10-25"}, [2, 1]),
    ({"added_since": "2026-10-26", "added_until": "2026-10-26"}, [4, 3]),
    ({"added_until": "2026-09-26"}, [0]),
    ({"recent_only": True}, [4, 3, 2, 1]),
    ({"recent_only": True, "recent_days": 1}, [4, 3]),
    ({"recent_only": True, "recent_days": 2}, [4, 3, 2]),
    ({"q": "cve-2026-4002"}, [2]),
    ({"q": "wIDGet"}, [2]),
    ({"q": "%_"}, [1]),
    ({"q": "O'Reilly"}, [1]),
    ({"q": "' OR 1=1 --"}, []),
    ({"q": "description"}, []),
    ({"q": "Example", "recent_only": True, "added_until": "2026-10-25"}, [2]),
])
def test_catalog_filters_order_pagination_and_calendar(dated_catalog, params, indices):
    client, original = dated_catalog
    response = client.get("/api/triage", params=params)
    assert response.status_code == 200, response.text
    result = response.json()
    assert [item["cve_id"] for item in result["items"]] == [original[index]["cveID"] for index in indices]
    assert result["filters"] == {**DEFAULT_FILTERS, **params}
    assert result["as_of_utc"] == "2026-10-26T23:00:00+00:00"
    assert result["catalog_total"] == 6 and result["data_mode"] == "REAL DATA"
    for item in result["items"]:
        index = next(index for index, kev in enumerate(original) if kev["cveID"] == item["cve_id"])
        assert item["kev"] == original[index]
        days = params.get("recent_days", 30)
        assert item["indicators"]["recent_kev"] is (index in ({3, 4} if days == 1 else {2, 3, 4} if days == 2 else {1, 2, 3, 4}))
    if "page" in params:
        assert result["total"] == 6 and result["pages"] == 3
        assert result["page"] == params["page"] and result["page_size"] == 2
    else:
        assert result["total"] == len(indices) and result["pages"] == 1


def test_all_criteria_combine_with_and(numeric_catalog):
    client, ids, _ = numeric_catalog
    params = {"q": ids[5], "added_since": "2026-10-20", "added_until": "2026-10-20",
              "nvd_state": "unavailable", "epss_state": "stale", "cvss_availability": "scored",
              "cvss_min": 9.8, "epss_min": 0.7, "recent_days": 7, "recent_only": True,
              "sort": "asc", "page": 1, "page_size": 1}
    result = client.get("/api/triage", params=params).json()
    assert result["filters"] == params
    assert result["total"] == 1 and result["pages"] == 1 and result["items"][0]["cve_id"] == ids[5]
    for key, value in {"nvd_state": "available", "epss_state": "available", "cvss_availability": "unscored",
                       "cvss_min": 10, "epss_min": 0.71, "recent_days": 6, "q": "not a source match",
                       "added_since": "2026-10-21", "added_until": "2026-10-19"}.items():
        query = {**params, key: value}
        # Keep dates valid while checking each date boundary independently.
        if key == "added_since":
            query["added_until"] = "2026-10-26"
        if key == "added_until":
            query["added_since"] = "2026-10-01"
        response = client.get("/api/triage", params=query)
        assert response.status_code == 200, response.text
        assert response.json()["total"] == 0, key
        assert response.json()["items"] == [] and response.json()["pages"] == 1
        assert response.json()["data_mode"] == "REAL DATA"
