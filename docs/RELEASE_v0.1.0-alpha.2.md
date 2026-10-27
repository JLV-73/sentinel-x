# v0.1.0-alpha.2 — Intelligence Triage Edition

SENTINEL X — NIGHTFALL by JLV LABS. This source version adds the validated
P1-B Intelligence Triage to the Alpha 1 baseline. PR #6 is merged into main.
Tag and GitHub Pre-release publication are a separate owner decision; these notes
do not assert that either exists.

## Intelligence Triage

- Read KEV exploitation evidence, every original CVSS version/provider, EPSS
  30-day probability and its separate percentile in one local view.
- Filter CVE/vendor/product, inclusive KEV-added dates, source states, CVSS/EPSS
  values and recency. Criteria combine with AND and remain independently visible.
- Preserve missing, not requested, unavailable, stale and zero as different states.
  Retained values remain identified by date, state and provenance.
- Keep FR/EN, applied filters, draft values, page and CVE-detail/back context.
- GET /api/triage reads one coherent local SQLite snapshot: no implicit collection,
  row/schema/history/control mutation, migration or new dependency.
- Standard SQLite WAL/SHM coordination files may be created even in mode=ro.
  Normal locking and committed WAL visibility remain; no immutable/nolock bypass.
- OSV/GHSA comparison is research only. No new data connector, scanner, inventory,
  automatic alert, autonomous AI, composite score or device-exposure diagnosis.

## Windows 11 / reproducibility

Follow README.md or README.fr.md: normal PowerShell, Set-Location $HOME,
Git/Python 3.11/Node.js 24/npm.cmd, fresh writable directory, project-local locked
venv/dependencies, pinned external CISA schema and START_SENTINEL.cmd.
The README's main clone follows integrated development, not an immutable Alpha 2
tag. Reproduce a release only with its actually published tag; before publication,
use the exact local candidate commit/source archive in the preparation handoff.
A fresh install starts NO DATA. CISA/NVD/EPSS collection remains explicit/manual.
Servers bind only 127.0.0.1; Ctrl+C stops the owned foreground launcher.
The on-demand backup command and failure guards remain in both READMEs.

## Validation scope

The merge source tree is identical to the reviewed and user-tested P1-B tree.
Hash-bound P1-B evidence includes 379 backend and 103 frontend tests, build,
46 real HTTP checks and real-data/CISA-only/NO DATA browser recipes.
Alpha 2 preparation changes documentation/version metadata only. The preparation
handoff distinguishes newly executed integration checks from reused P1-B evidence;
no old test result is represented as a fresh complete suite or fresh install.

## Limits and rights

Experimental local source-only prototype, not a security guarantee, certification
or hosted product. Manual collection, partial NVD coverage, provider quotas and
freshness/absence/error states still apply. The existing large frontend bundle,
AnyIO deprecation and NVD cveId deprecation remain outside this preparation.
The private package.json version/UI badge are historical labels; VERSION and the
actually published Git tag identify a release, not those internal legacy labels.

Alpha 1 and historical tags are preserved. No database, backup, raw API cache,
credentials, runtime logs or external CISA schema is shipped. Original project
code remains Apache-2.0; dependency/data/trademark rights stay separate. Preserve
LICENSE, NOTICE, COPYRIGHT.md and THIRD_PARTY_NOTICES.md. Issues #3 and #4 remain
outside this scope. No new product functionality is introduced after P1-B.
