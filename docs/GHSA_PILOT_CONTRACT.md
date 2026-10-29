# P1-C — bounded GHSA pilot integration contract

Branch p1c/ghsa-intelligence, stable base ea199eacdee37479a621430af6cef86a3e1f0070.
Only an extra GHSA section on existing CVE detail. No catalogue-wide GHSA query,
new cockpit, OSV connector, scheduler, automatic refresh, score or asset diagnosis.

## Read/write contract

- `GET /api/intelligence/ghsa/{cve_id}`: local cache only, validates exact local KEV
  CVE; no network, lease acquisition, raw file or attempt creation.
- `POST /api/intelligence/ghsa/{cve_id}?refresh=true|false`: explicit user collection.
  Same existing Host guard; require exact allowed Origin and X-Sentinel-Request: sync,
  reject bodies, unknown/duplicate params and nonliteral refresh values. Default false:
  serve a prior successful cache without network (including successful absence);
  true explicitly requests a new source read, subject to persistent cooldown.
- Both return `GhsaResult`: `{cve_id, ghsa: SourceData<GhsaData>, control}`.
- `SourceData` has existing state/stale/retained_after_error/collected_at/source_date/
  data/provenance/last_attempt/last_success meanings. TTL 24h via existing source_fields.
- `GhsaData = {date: string|null, advisories: Advisory[]}`. date is the maximum original
  updated_at among returned records, not a new advisory/collection date. A complete
  successful empty array is stored as null -> absent, never a synthetic advisory.
- `Advisory` preserves the original reviewed record fields: ghsa_id,cve_id,type,
  html_url,summary,description,severity,cvss,cvss_severities,identifiers,vulnerabilities,
  published_at,updated_at,github_reviewed_at,nvd_published_at,withdrawn_at, etc.
  Vulnerability entries preserve package.ecosystem/name, vulnerable_version_range,
  first_patched_version (nullable); source values/strings remain unchanged.
- `control = {next_request_at: string|null, freshness_hours:24,
  minimum_interval_seconds:65,max_advisories:100, attribution:{name,url,license,license_url}}`.
  Attribution name GitHub Advisory Database; URL https://github.com/advisories;
  license CC-BY-4.0; license_url https://creativecommons.org/licenses/by/4.0/ .
- Errors: 404 unknown local CVE, 422 invalid request, 409 busy/cooldown,
  502 collection failure with detail `{error,attempt,cached}` (cached is GhsaResult).
  Existing P0/P1-A/P1-B response shapes remain unchanged.

## Source, quota and storage boundary

Fixed anonymous official endpoint https://api.github.com/advisories with
`cve_id=<exact local CVE>&type=reviewed&per_page=100`; pin supported GitHub API
version, no auth/environment token, redirects or arbitrary source URLs.
One bounded page/HTTP request maximum per manual action; if Link rel=next appears,
fail and preserve cache rather than present partial results as exhaustive/absent.
Omit is_withdrawn: official documentation describes it as a filter to ONLY withdrawn
records. Validate and preserve withdrawn_at when returned; never hide retained withdrawals.

Reserve requests durably at >=65s intervals for this source, before actual HTTP;
never sleep/retry automatically. Respect source 403/429, Retry-After and rate-limit
remaining/reset (including success with remaining=0). GET/cached lookup does not
consume the source quota. Shared-IP activity outside this app can still exhaust
GitHub's anonymous quota; retain valid prior data and report unavailable/cooldown.

Reuse existing intelligence_* tables with source='ghsa' (no source CHECK prevents
this), keeping ENDPOINTS for NVD/EPSS UNCHANGED so their APIs/coverage stay stable.
Prefer a narrowly scoped GHSA service reusing stable lease/journal/raw/storage/view
helpers; override only GHSA acquisition/reservation/client collection as necessary.
Create the additive ghsa control row lazily on first explicit collection, not GET.
No destructive migration or legacy row alteration. Raw JSON useful responses are
hashed/retained locally under intelligence_raw/ghsa; preserve data on failures and
require durable commit/readback before claiming success. Cooperative download budget
and byte cap must include headers/chunks/EOF; no immutable/nolock or TLS bypass.

## Interface

GHSA panel in Detail only. Reuse SourceMetadata/Field/JsonDisclosure/SafeLink and
useVerifiedCollection where suitable, with CVE-scoped remount/state safety. Explicit
search/refresh button, unknown/none/unavailable/retained/stale distinctions, quota
next_request_at, original reviewed/withdrawn status, dates, packages/ranges/fixes,
original severity/CVSS and attribution/license/modification disclosure.
FR/EN labels only; original advisory text/identifiers/ranges stay intact. No Markdown
HTML execution. Mutation follows local readback; page open/language switch/GET never
collects. Triage and other connectors retain current behavior.
