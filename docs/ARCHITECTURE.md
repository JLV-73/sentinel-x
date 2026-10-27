# Architecture and version boundaries

SENTINEL X is a local defensive intelligence prototype, not an asset scanner.

| Reference | Implemented scope |
|---|---|
| `main` / `p0.1-international-stable` | P0.1: CISA KEV ingestion, SQLite, API, bilingual NIGHTFALL cockpit |
| `p1/intelligence-core` | P1-A: the stable foundation plus targeted NVD/CVSS and FIRST EPSS enrichment |

P1-A is not merged into stable main. Read the README for the checked-out branch.

## Shared foundation

React + TypeScript + Vite + Tailwind + ECharts call a local FastAPI API. SQLite
stores a validated current CISA catalogue and import journal. Manual collection
tries the canonical CISA feed, then its official mirror if necessary. Validation
checks schema, identifiers, dates, uniqueness and counts before atomic commit.
Failures retain the last validated snapshot. No source collection at startup.

Both development servers bind only `127.0.0.1` (frontend 5177, backend 8007).
Write endpoints enforce Host/Origin and a custom request header. This is a
single-user local boundary, not multi-user authentication or public hardening.

## P1-A extension — development branch only

Separate SQLite tables preserve NVD/EPSS data, attempts, freshness and raw-reply
provenance. Local GETs never fetch upstream data. NVD is fetched/refreshed
explicitly per local KEV CVE; EPSS refresh uses sequential small batches of local
KEV identifiers. Source URLs are fixed and TLS verified; no key is required.

CVSS versions/providers remain separate. EPSS probability and percentile remain
distinct. No score is invented or combined into an exposure/risk score. CISA
records are never overwritten with another source's fields.

Five states distinguish available, not requested, officially absent, temporarily
unavailable and stale data. Failed updates retain valid cached values with a
warning. Lease ownership is transaction-fenced; deferred SQLite cleanup cannot
silently replace a committed result. Old UI reads cannot overwrite a newer
verified collection result.

Runtime data, raw replies, backups, caches, environments and workstation evidence
are not in this repository. `scripts/backup.py` makes an on-demand SQLite online
backup and SHA-256 manifest. On P1-A it also includes enrichment raw replies.
Restore in an isolated directory before considering any production replacement.

No Docker, background scheduler, autonomous AI, scanner, telemetry integration,
remote dashboard or public deployment is implemented.
