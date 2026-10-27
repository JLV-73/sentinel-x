# SENTINEL X — NIGHTFALL

**Defensive cyber intelligence, with traceable facts rather than simulated threats.**  
JLV LABS · Private prototype · [Français](README.fr.md)

**Stable P0.1 — INTERNATIONAL EDITION.** This main branch includes CISA KEV only. NVD/CVSS and FIRST EPSS enrichment are on the separate `p1/intelligence-core` branch, not here.

![Genuine NIGHTFALL CISA overview capture](docs/images/overview-en.png)

*App-only capture from actual CISA validation; dated source content, not a live
attack feed. No raw catalogue, runtime database or private workstation evidence is shipped.*

## What works

- English/French NIGHTFALL cockpit, overview charts and CISA catalogue.
- Search, filters, pagination and detailed CVE records.
- Manual CISA sync: validation, atomic SQLite import, idempotence and SHA-256/source provenance.
- Explicit empty/error/stale states; failed sync preserves previously validated data.
- Local FastAPI/SQLite backend and React/TypeScript/Vite/Tailwind/ECharts frontend.


## Install and run — Windows 11

Prerequisites: GitHub access to this private repository, Git, Python **3.11** and
Node.js **24** with npm. These are prerequisites, not globally installed by the
project. Python/npm dependencies stay inside the checkout. Use a normal local
filesystem supporting hard links for the atomic schema installation.

Open **PowerShell**, not a Python prompt, and choose a dedicated directory:

```powershell
git clone https://github.com/JLV-73/sentinel-x.git
cd sentinel-x
py -3.11 -m venv .venv
New-Item -ItemType Directory -Force -Path .cache/pip,.cache/tmp | Out-Null
$env:TEMP = Join-Path (Get-Location) ".cache/tmp"
$env:TMP = $env:TEMP
.\.venv\Scripts\python.exe -I -m pip --isolated install --cache-dir .cache/pip -r backend/requirements-lock.txt
.\.venv\Scripts\python.exe -I tools/bootstrap_schema.py
npm --prefix frontend ci
.\START_SENTINEL.cmd
```

`TEMP`/`TMP` above change only this PowerShell session, not Windows global settings.
The bootstrap obtains a pinned official validation schema **locally**, verifies its
SHA-256 and never overwrites existing different bytes. This external resource is
intentionally not redistributed; see [schema setup](docs/SCHEMA_SETUP.md).

Open http://127.0.0.1:5177 in your browser yourself. API health:
http://127.0.0.1:8007/api/health . The launcher opens no personal browser, installs
no service and refuses occupied ports instead of killing another process.

A fresh checkout starts with **NO DATA**. Use **DATA CONTROL → Synchronize CISA**
once; network access is necessary and official access restrictions are respected.
No demo data silently feeds real indicators, and startup does not collect sources.

**Stop:** press Ctrl+C in the launcher console; confirm termination if Windows asks.
Do not expose these development servers beyond `127.0.0.1` or enable tunnels.

## Verify

```powershell
.\.venv\Scripts\python.exe -I -m pytest backend/tests -q
.\.venv\Scripts\python.exe -I -m unittest discover -s scripts -p "test*.py" -v
.\.venv\Scripts\python.exe -I -m unittest discover -s tools -p "test*.py" -v
npm --prefix frontend test
npm --prefix frontend run build
```

Tests use isolated fixtures, not your runtime database. These commands do not
launch browser recipes or refresh official feeds. The historical suites passed
for this source snapshot; see [verification](docs/VERIFICATION.md).

**On-demand backup:** `.\.venv\Scripts\python.exe -I scripts/backup.py` creates a
SQLite online backup under `data/backups/` with source files and SHA-256 manifest.
Restore and verify in a separate directory before replacing runtime data. Never
commit databases, raw caches, backups, environments or dependency trees.

## Read next

[Architecture](docs/ARCHITECTURE.md) · [Sources and interpretation](docs/SOURCES.md) ·
[Roadmap](docs/ROADMAP.md) · [Clean-history map](docs/HISTORY_MAP.md) ·
[Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) ·
[Changelog](CHANGELOG.md) · [Third-party notices](THIRD_PARTY_NOTICES.md)

## Boundaries and license

This is a local, single-user defensive prototype: no scanner, exploit, asset
inventory, automatic alerts, autonomous AI, telemetry connector, public deployment
or multi-user authentication. A KEV entry does not establish that your devices
are vulnerable; CISA due dates are not general French legal deadlines.

Current limits include a large frontend bundle and a dependency deprecation
warning. P1-A adds provider quotas, cooperative—not absolute—network deadlines,
partial NVD coverage, cache freshness and a deprecated-but-tested NVD parameter;
its source integration must be reviewed before any scaled data redistribution.

**Project license undecided; rights otherwise reserved by default.** This private
access is not an open-source grant. MIT/Apache-2.0/GPLv3/AGPLv3 are compared in
[License options](docs/LICENSE_OPTIONS.md); no definitive license is imposed.
Public visibility, contributor licensing, structural merges and releases require
explicit JLV approval. Package-manifest version numbers are not release claims.
