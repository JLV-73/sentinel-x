# P1-B Intelligence Triage — small integration contract

Branch: p1b/intelligence-engine, based on R1 main. One new read-only view at
`#triage`, linked to existing `#cve/<id>`. No collector, schema migration,
dependency, scheduler, risk score or OSV/GHSA connector added.

## GET /api/triage

Existing Host guard applies. GET reads one consistent SQLite snapshot; no
application row/schema/history/control writes, network requests, source refresh,
new attempts, control lease or application/raw file creation.

SQLite boundary — explicit correction for P1B-RO-WAL-001: the original blanket
"no ... file creation" guarantee was too strong. SQLite may create/manage its
`-wal`/`-shm` coordination files even with `mode=ro`; these standard coordination
effects are permitted, not application-data writes or implicit collection.
Keep normal read-only transactions, locking and visibility of committed WAL
changes; do not bypass coordination with `immutable=1` or `nolock`. Existing
databases remain compatible without migration or journal-mode changes. GET does
not delete, clean up, repair or change PRAGMAs on the user database. Unchanged-file
checks on a legacy DELETE-journal fixture establish that tested case only, not
an absolute zero-filesystem-side-effect guarantee for WAL databases.

Parameters (reject unknown or duplicate parameters, invalid values with 422):
- q: literal CVE/vendor/product substring, default empty, max 200.
- added_since / added_until: optional strict ASCII YYYY-MM-DD, inclusive;
  since > until is invalid.
- nvd_state / epss_state: all (default), available, not_requested, absent,
  unavailable, stale, needs_attention. The stale filter selects stale=true even
  when a failed latest attempt makes primary state unavailable. needs_attention
  selects primary state != available OR stale=true.
- cvss_availability: all (default), scored, unscored (presence of actual metrics).
- cvss_min: optional finite inclusive 0..10; matches ANY original CVSS metric
  >= minimum, preserving every version/provider instead of choosing a composite.
- epss_min: optional finite inclusive 0..1 probability (NOT percent).
  UI accepts 0..100 percent and converts once to wire probability. Percentile
  is displayed separately and never substituted for the probability.
- recent_days: integer 1..3650, default 30. Recent means inclusive UTC calendar
  interval [today-(days-1), today], not first_seen import time or attack time.
- recent_only: boolean false by default; filters that recent criterion only.
- sort: asc/desc by (dateAdded,cveID), default desc; deterministic.
- page: >=1 default1; page_size: 1..100 default20; empty total pages>=1.

All filters combine with AND. Numeric filters evaluate any retained source value
(including stale/unavailable-after-error); missing data does NOT match, not zero.
The UI must disclose this retained-value policy alongside availability filters.

Response:
```
{
 data_mode: "REAL DATA" | "NO DATA",
 as_of_utc: string,
 catalog_total: number, total: number, page: number, pages: number, page_size: number,
 filters: { all normalized/defaulted query fields },
 cisa_provenance: ImportRecord | null,
 items: [{
   cve_id: string,
   kev: original official CISA vulnerability object (do not translate/reclassify),
   nvd: TriageSource<NvdData>, epss: TriageSource<EpssData>,
   indicators: {
     recent_kev: boolean,
     cvss_threshold_met: boolean|null, epss_threshold_met: boolean|null,
     nvd_needs_enrichment: boolean, epss_needs_enrichment: boolean
   }
 }]
}
```
TriageSource<T> keeps existing SourceData fields state,stale,retained_after_error,
collected_at,source_date,data,provenance; omits last_attempt and last_success
histories to avoid repeating all EPSS batch URLs for every row. Existing detail
remains the place to inspect full attempt history. No P1-A endpoint shape changes.
Threshold indicators are null when threshold or source value is absent; otherwise
true/false, never a proprietary priority/risk ranking. Known KEV presence is an
explicit source fact for each row, not proof that any asset is affected.

## Implementation / verification

Backend may extract a pure existing-source state helper shared with P1-A _view,
but preserve the existing semantics and all 217 regression tests. Prefer bulk
cache/target reads in one snapshot and one frozen as_of time over N+1 attempts
or repeated JSON decoding. No schema/data rewrite. Test zero vs missing, all
five source states, retained-after-error/stale combinations, multiple CVSS metrics,
probability units, strict dates/ranges, pagination, SQL-like literal searches,
readonly/no-network invariance and old cache compatibility.

Frontend uses current NIGHTFALL components/tokens: an Explore/Inspect work surface,
compact filter bar, source-separated facts, contextual independent criterion tags,
clear incomplete/loading/error/empty states, pagination and detail navigation.
One coherent new screen, not a new dashboard family. FR/EN preserves filter,
page and selected CVE; show original source values/versions/providers, collection
and source dates, full provenance hash/URL (collapsible if necessary), official
CISA/NVD/FIRST references, no false inventory or score composite. Accessible
44px controls; no document overflow at 1366/1600px; normal table scrolling allowed.
