# 0.1.0 — First Stable Release

SENTINEL X — NIGHTFALL | First Stable Release by JLV LABS.
Source version 0.1.0 defines the R3 baseline described below. GitHub Releases
records the actual publication status; a source label or versioned notes alone
do not establish that a Release is available.

## Same validated capabilities as Alpha 2

- CISA KEV: explicit/manual validated import, catalogue search/filter/pagination,
  CVE details, charts of KEV additions and traceable source/import provenance.
- NVD/CVSS: targeted manual enrichment with original versions/providers/vectors,
  availability, dates and freshness. No exhaustive NVD collection.
- FIRST EPSS: manual refresh for local KEV CVEs; 30-day exploitation probability
  distinct from percentile, with dates, availability and provenance.
- Intelligence Triage: independent local multi-signal filters, original values,
  missing/zero/error/stale distinctions, retained-value disclosure, FR/EN and
  filter/page/draft/detail-back continuity. No invented aggregate risk score.

## R3 change boundary — version coherence only

VERSION, frontend/package.json and root metadata in frontend/package-lock.json
identify source version 0.1.0. The cockpit derives its badge from VERSION rather
than the historical hardcoded v1.0. npm metadata mirrors the source version and
is checked; dependencies, resolutions and integrity values do not change.
No backend behavior, collector, data schema, functional workflow, architecture,
provider or dependency is added or modified. Documentation and its actual capture
are updated to reflect the version and already-integrated P1-B.

## Local Windows 11 installation

Follow README.md or README.fr.md, from normal non-administrator PowerShell:
Set-Location $HOME, Git, Python 3.11, Node.js 24/npm.cmd, a fresh writable directory,
local locked venv/npm installation and pinned external CISA schema bootstrap.
The documented stable installation selects the immutable v0.1.0 tag, not a
moving development branch. This tag becomes usable after publication; a detached
HEAD is normal for a release-tag checkout. Check GitHub Releases for availability.
Published Alpha 1/2 and historical tags stay frozen.

START_SENTINEL.cmd runs foreground loopback servers on 127.0.0.1:5177 and :8007.
A new installation starts NO DATA, never a silent demo catalogue. Collection is
manual. Ctrl+C in the owned launcher stops both servers; do not stop an unknown
process to free ports. On-demand backup stays local and outside Git.

## Verification and source distribution

The R3 validation handoff records the exact source reference and targeted
installation, metadata, TypeScript/build, API/cockpit/version and data-integrity
checks. Reused P1-B/R2 checks are bound to unchanged functional/dependency hashes,
not claimed as fresh full suites. Repository changes remain governed by review,
CODEOWNERS requirements and explicit owner authorization; no automatic bypass.

Stable distribution profile: tag v0.1.0; public GitHub Release named
SENTINEL X — NIGHTFALL | First Stable Release; prerelease=false, draft=false,
eligible for Latest. Standard source ZIP/TAR.GZ only; no Windows binary or installer.

## Meaning of stable, limitations and rights

Stable identifies the selected release baseline. It is not a security certification,
a vulnerability-free guarantee, production suitability assurance or authorization
to expose this local prototype as a public service. No automatic network monitoring,
scanner, inventory, autonomous alert/AI, device-exposure inference or hosted service.
Manual source quotas, partial NVD coverage, retained stale/unavailable values,
cooperative download budgets, existing large bundle and dependency deprecations
remain. SQLite mode=ro can create WAL/SHM coordination files without application
row/schema mutation; normal locking and committed WAL visibility are preserved.

Apache-2.0 covers original owned code; retain LICENSE/NOTICE, COPYRIGHT.md and
THIRD_PARTY_NOTICES.md. Provider data, third-party dependencies and trademarks
retain separate terms. No credentials, local database, backup, raw API cache,
private evidence or external schema is bundled. CONTRIBUTING.md and SECURITY.md
provide contribution/private-reporting paths. No C1, P1-C, P2 or P3 work is engaged.
After verified stable publication, development is PAUSED pending a new applicable GO.
