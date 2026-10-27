"""Local-only, compact intelligence triage; never refreshes source data."""
from contextlib import closing, contextmanager
from datetime import date, timedelta, timezone
from typing import Literal
import json
import re
import sqlite3
from fastapi import HTTPException, Query, Request

from .intelligence import source_fields

SourceState = Literal["all", "available", "not_requested", "absent", "unavailable", "stale", "needs_attention"]

DEFAULT_FILTERS = {
    "q": "", "added_since": None, "added_until": None,
    "nvd_state": "all", "epss_state": "all", "cvss_availability": "all",
    "cvss_min": None, "epss_min": None, "recent_days": 30,
    "recent_only": False, "sort": "desc", "page": 1, "page_size": 20,
}


@contextmanager
def read_snapshot(cisa):
    # mode=ro also prevents accidentally creating an empty DB on a missing path.
    # Do not use immutable=1: it would ignore WAL commits and concurrency locks.
    try:
        with closing(sqlite3.connect(cisa.db_path.resolve().as_uri() + "?mode=ro", uri=True, timeout=5)) as db:
            db.row_factory = sqlite3.Row
            with db:
                db.execute("BEGIN")
                yield db
    except sqlite3.OperationalError as error:
        raise HTTPException(503, "Local triage snapshot unavailable") from error


def listing(cisa, filters):
    as_of = cisa.clock().astimezone(timezone.utc)
    with read_snapshot(cisa) as db:
        catalog = [json.loads(row[0]) for row in db.execute("SELECT payload FROM vulnerabilities")]
        provenance = cisa.last_success(db)
        cache = {(row["source"], row["cve_id"]): row for row in db.execute("SELECT * FROM intelligence_cache")}
        targets = {(row["source"], row["cve_id"]): row for row in db.execute("""
            SELECT target.* FROM intelligence_targets AS target
            JOIN (SELECT source,cve_id,MAX(attempt_id) AS attempt_id
                  FROM intelligence_targets GROUP BY source,cve_id) AS latest
            USING (source,cve_id,attempt_id)
        """)}
    lower = (as_of.date() - timedelta(days=filters["recent_days"] - 1)).isoformat()
    upper = as_of.date().isoformat()
    needle = filters["q"].casefold()
    items = []
    for kev in catalog:
        recent = lower <= kev["dateAdded"] <= upper
        if (needle and not any(needle in kev[field].casefold() for field in ("cveID", "vendorProject", "product"))
                or filters["added_since"] is not None and kev["dateAdded"] < filters["added_since"]
                or filters["added_until"] is not None and kev["dateAdded"] > filters["added_until"]
                or filters["recent_only"] and not recent):
            continue
        value = kev["cveID"]
        sources = {source: source_fields(source, cache.get((source, value)), targets.get((source, value)), as_of)
                   for source in ("nvd", "epss")}
        metrics = sources["nvd"]["data"]["cvss"] if sources["nvd"]["data"] is not None else []
        epss = sources["epss"]["data"]
        cvss_met = threshold_met([metric["base_score"] for metric in metrics], filters["cvss_min"])
        epss_met = threshold_met([epss["epss"]] if epss is not None else [], filters["epss_min"])
        indicators = {"recent_kev": recent,
                      "cvss_threshold_met": cvss_met, "epss_threshold_met": epss_met,
                      **{source + "_needs_enrichment": view["state"] != "available" or view["stale"]
                         for source, view in sources.items()}}
        if not all(state_matches(sources[source], filters[source + "_state"])
                   for source in ("nvd", "epss")):
            continue
        availability = filters["cvss_availability"]
        if (availability == "scored" and not metrics) or (availability == "unscored" and metrics):
            continue
        # Retained values remain filterable regardless of primary source state.
        # Missing values never become zero (including an inclusive minimum of 0).
        if (filters["cvss_min"] is not None and cvss_met is not True
                or filters["epss_min"] is not None and epss_met is not True):
            continue
        items.append({"cve_id": value, "kev": kev, **sources, "indicators": indicators})
    items.sort(key=lambda item: (item["kev"]["dateAdded"], item["cve_id"]), reverse=filters["sort"] == "desc")
    total = len(items)
    page, page_size = filters["page"], filters["page_size"]
    offset = (page - 1) * page_size
    return {
        "data_mode": "REAL DATA" if catalog else "NO DATA", "as_of_utc": as_of.isoformat(),
        "catalog_total": len(catalog), "total": total, "page": page,
        "pages": max(1, (total + page_size - 1) // page_size),
        "page_size": page_size, "filters": filters,
        "cisa_provenance": provenance, "items": items[offset:offset + page_size],
    }


def threshold_met(values, minimum):
    return None if minimum is None or not values else any(value >= minimum for value in values)


def state_matches(view, selected):
    if selected == "stale":
        return view["stale"]
    if selected == "needs_attention":
        return view["state"] != "available" or view["stale"]
    return selected == "all" or view["state"] == selected


def install_triage_route(app, cisa):
    @app.get("/api/triage")
    def triage(request: Request, q: str = Query("", max_length=200),
               added_since: str | None = None, added_until: str | None = None,
               nvd_state: SourceState = "all", epss_state: SourceState = "all",
               cvss_availability: Literal["all", "scored", "unscored"] = "all",
               cvss_min: float | None = Query(None, ge=0, le=10, allow_inf_nan=False),
               epss_min: float | None = Query(None, ge=0, le=1, allow_inf_nan=False),
               recent_days: int = Query(30, ge=1, le=3650), recent_only: bool = False,
               sort: Literal["asc", "desc"] = "desc", page: int = Query(1, ge=1),
               page_size: int = Query(20, ge=1, le=100)):
        for key in request.query_params:
            if key not in DEFAULT_FILTERS or len(request.query_params.getlist(key)) != 1:
                raise HTTPException(422, "Unknown or duplicate triage query parameter")
        for key, value in (("added_since", added_since), ("added_until", added_until)):
            if value is not None:
                try:
                    if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value) is None:
                        raise ValueError("Expected ASCII YYYY-MM-DD")
                    date.fromisoformat(value)
                except ValueError as error:
                    raise HTTPException(422, "Invalid " + key + " date") from error
        if added_since is not None and added_until is not None and added_since > added_until:
            raise HTTPException(422, "added_since must not exceed added_until")
        return listing(cisa, {"q": q, "added_since": added_since, "added_until": added_until,
                              "nvd_state": nvd_state, "epss_state": epss_state,
                              "cvss_availability": cvss_availability, "cvss_min": cvss_min, "epss_min": epss_min,
                              "recent_days": recent_days, "recent_only": recent_only, "sort": sort,
                              "page": page, "page_size": page_size})
