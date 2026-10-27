# v0.1.0-alpha.1 — First Official Alpha

SENTINEL X — NIGHTFALL by JLV LABS is an experimental local defensive intelligence
prototype. This Alpha integrates existing P0.1 + P1-A, not a new functional phase.

## Included

- CISA KEV: validated manual catalogue sync, search, filters, pagination, detail,
  source hashes/history, charts of additions and last-valid-data preservation.
- NVD/CVSS: targeted explicit fetch for local KEV CVEs, original metric versions,
  vectors/providers, availability, freshness and provenance.
- FIRST EPSS: explicit local-KEV refresh, 30-day exploitation probability and
  relative percentile with source date/provenance, separate from CVSS.
- NIGHTFALL FR/EN cockpit: React/TypeScript/Vite/Tailwind/ECharts + FastAPI/SQLite.

## Install Windows 11

Follow README.md or README.fr.md: normal PowerShell, Set-Location $HOME,
Git/Python 3.11/Node.js 24/npm.cmd, fresh clone, local venv/locked dependencies,
pinned external schema, START_SENTINEL.cmd, cockpit 127.0.0.1:5177 and API :8007.
A new install starts NO DATA. Run CISA sync manually, then optional NVD/EPSS actions.
Ctrl+C stops owned servers. On-demand backup stays local; never commit runtime data.
The release tag provides a reproducible reference; a detached HEAD is expected.

## Verification and publication gate

Tests and live-source checks must run on the candidate actually selected for R1.
The Release notes/report record completed results, candidate and final commit/tree;
old P1-A results alone do not establish R1 success. Source archives are GitHub's
standard tag archives only: no executable, installer, container or extra package.

## Limits

Local experimental prototype: no security guarantee, certification, automatic
monitoring, scanner, inventory, notifications or autonomous AI. No device exposure
inference, fabricated attack feed or composite risk score. Provider quotas, manual
refresh, partial NVD coverage, stale/absent/unavailable states and cooperative
network budgets apply. NVD cveId is deprecated but retained pending approved work.
The large frontend bundle and dependency deprecation remain documented limitations.

No SQLite database, backup, source-response cache, credentials or external schema
is distributed. Provider-data rights are separate from source-code rights.
Apache-2.0 applies to original owned project code; preserve LICENSE/NOTICE and
THIRD_PARTY_NOTICES. GitHub Issues and CONTRIBUTING.md are the community paths;
security reports use SECURITY.md. Issues #3 and #4 are not implemented by R1.
