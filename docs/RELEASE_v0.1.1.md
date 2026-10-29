# 0.1.1 — GHSA Intelligence Edition

SENTINEL X — NIGHTFALL | GHSA Intelligence Edition by JLV LABS.

This source baseline integrates P1-C by PR #9 (2026-10-29), on top of the preserved
v0.1.0 First Stable Release. These versioned notes do **not** create a tag or publish
a Release. Check [GitHub Releases](https://github.com/JLV-73/sentinel-x/releases)
for actual availability. The immutable v0.1.1 checkout is usable after publication;
a detached HEAD is normal.

## Four separate official sources

- **CISA KEV:** explicit validated catalogue import, search/filter/pagination, CVE
  details, catalogue-addition charts and traceable import/source provenance.
- **NVD/CVSS:** targeted manual enrichment for local KEV CVEs; original versions,
  providers, scores and vectors with availability, dates and freshness. No bulk NVD lookup.
- **FIRST EPSS:** manual refresh for local KEV identifiers; 30-day exploitation
  probability remains distinct from percentile, dates and provenance.
- **GitHub Advisory Database (GHSA):** an explicit anonymous lookup for one local
  CVE, reviewed public advisories only; original IDs, source URL, packages/ecosystems,
  affected ranges, first fixes, dates, severity/vectors and withdrawal status.

The bilingual NIGHTFALL CVE detail includes GHSA; local Intelligence Triage retains
its independent KEV/NVD/EPSS filters. GHSA does not become a new composite score,
triage ranking, package inventory match or equipment-exposure conclusion.

## Bounded GHSA pilot and focused final correction

One official API response page per explicit lookup, at most 100 advisories; a next
page causes an explicit pilot-limit failure, not a silently partial result. Requests
are durably paced at a minimum 65-second interval and respect provider cooldowns.
No mandatory API key, automatic retry, startup collection or catalogue-wide query.
Anonymous quota is shared by IP; local pacing cannot reserve capacity used elsewhere.

Unrequested lookup, confirmed empty reviewed response, unavailable source, stale
snapshot and retained-after-error data remain distinct. Multiple advisories remain
separate. Withdrawn records stay documentary, not active remediation advice.
Successful responses retain original JSON, source URL/date and SHA-256; local
readback confirms an explicit write before the UI announces verified success.
The cache reuses additive source=ghsa rows without replacing the legacy schema/data.

The final correction accepts `string | null` for `vulnerable_version_range` and shows
exactly **Non renseigné / Not specified** when absent. Provided strings remain
unchanged; the original source JSON still contains the original null/string value.
No other functional workflow, provider, dependency or architecture is changed.

## Versioning and validation boundary

Root VERSION, npm package/root lock metadata and the existing VERSION-derived
cockpit badge all identify **0.1.1**. They were already coherent after P1-C; release
preparation verifies them instead of regenerating metadata or dependency resolutions.

The R4 handoff records the exact corrected head, merged main commit and local
release-candidate commit/tree. New checks cover the bilingual present/null case,
JSON preservation, 28 targeted GHSA/version/App tests, TypeScript/Vite build and
an independent focused review. Older P1-C backend/API/browser evidence is reused
only for unchanged source/dependency hashes, dated separately; it is not claimed
as a newly executed full suite or a new GHSA collection.

## Local source installation and distribution

Follow README.md / README.fr.md: Windows 11, normal non-administrator PowerShell,
Git, Python 3.11, Node.js 24/npm.cmd, a new writable directory, locked project-local
dependencies and the pinned official external CISA schema bootstrap. Stable setup
selects immutable v0.1.1 **after publication**. The earlier published v0.1.0 checkout
remains available without GHSA; do not overwrite an existing working copy or data.

START_SENTINEL.cmd keeps loopback services in the foreground (127.0.0.1:5177 and
:8007). A fresh installation starts NO DATA; collection requires explicit actions.
Stop only the owned launcher with Ctrl+C. On-demand backups stay local/outside Git.
The operational, P1-B demonstration and JLV P1-C clones/launchers are not replaced
by this source candidate.

Intended source-only distribution: tag v0.1.1 and a GitHub Release named
**SENTINEL X — NIGHTFALL | GHSA Intelligence Edition**, standard ZIP/TAR.GZ sources.
No binary, installer, runtime database, backup, credential or private evidence is
bundled. Preparation is local only; even a GitHub draft Release needs a separate GO.

## Rights and limits

Original project code remains Apache-2.0. Retain LICENSE/NOTICE, COPYRIGHT.md,
THIRD_PARTY_NOTICES.md and actual dependency/provider terms. GHSA data and the
explicitly attributed, unmodified public offline test fixture are **CC-BY-4.0**,
GitHub Advisory Database and its contributors; they are not relicensed Apache-2.0.
Runtime source caches are not shipped. Embedded GitHub EPSS stays original JSON,
not a substitute for the separately dated direct FIRST source.

No security certification, vulnerability-free guarantee or authorization to expose
this local prototype publicly. No scanner, SBOM/inventory import, autonomous alert,
webhook/email/scheduler, OSV connector, Chiara/MCP integration or user-device diagnosis.
Download deadlines are cooperative, not hard wall-clock limits; source quotas,
incomplete reviewed coverage, retained stale values and existing build/dependency
warnings remain. CONTRIBUTING.md and SECURITY.md retain the contribution/private
reporting paths. P2, P3 and C1 require separate authorization.
