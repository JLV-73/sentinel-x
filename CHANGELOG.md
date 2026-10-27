# Changelog

Milestone history, not a semantic-version release series. Application milestones below are dated **2026-10-26**; GitHub Foundation is dated **2026-10-27**. These entries record completed local development/validation at the time; they do not claim a GitHub Release has been published or that checks were rerun for a later checkout.

The First Alpha integrates **P0.1 + P1-A** on its main candidate. The original CISA-only baseline remains frozen at `p0.1-international-stable`; [`p1/intelligence-core`](https://github.com/JLV-73/sentinel-x/tree/p1/intelligence-core) remains a preserved development reference. Earlier milestone entries describe their historical scopes. Clean-publication history is separate from the private local archive.

## v0.1.0-alpha.1 — First Official Alpha source — 2026-10-27

- Integrates the existing P0.1 foundation and P1-A intelligence core into one main candidate.
- Includes manual CISA KEV, targeted NVD/CVSS and FIRST EPSS with separate provenance/freshness.
- Preserves D1 writable-home Windows setup, failure guards, npm.cmd, local backup and contribution paths.
- Resolves README-only merge conflicts by preserving D1 and updating the version presentation.
- No new functional module, scanner, autonomous alert/AI, hosted service or bundled runtime data.
- Intended publication is a source-only GitHub pre-release after candidate verification and required approval.
- Community issues #3 and #4 remain open and outside R1.

## G2 — Public repository launch — 2026-10-27

- Selected Apache-2.0 for JLV-owned original project code; added official LICENSE,
  project NOTICE and separated third-party terms.
- Prepared public FR/EN documentation and Apache-2.0 contribution terms without
  a CLA or copyright assignment. Private security reporting uses GitHub.
- Preserved stable/development source separation and the immutable stable tag.
- No release, package, binary, source-engine change or Actions automation.

## GitHub Foundation — 2026-10-27 — private preparation

- Prepared a deliberately new sanitized Git history and version-specific international presentation.
- Added contribution/security/conduct rules and Issues/PR templates; no public onboarding or release.
- Audited dependency declarations; project license remains undecided.
- Excluded private evidence, runtime data and ancillary schema redistribution; pinned local schema installation preserves exact historical bytes.

## P1-A — Core Intelligence — 2026-10-26 — development branch only

- Added targeted, explicitly requested NVD/CVSS enrichment and manual FIRST EPSS collection for the local CISA catalogue; kept source attribution, versions, score dates, provenance and availability states distinct.
- Preserved CISA source payloads and the **229** original P0.1 translation values; expanded to **320** typed translation keys.
- Recorded validation: **217 backend**, **74 frontend**, **9 operations tests** (also 9 under optimized Python), and successful frontend build.
- Historical source coverage in the validation snapshot: **12 NVD-enriched CVEs** and **1,756 EPSS-scored CVEs** in a **1,756-CVE** local KEV catalogue. This is not a live coverage guarantee, a bundled dataset or exhaustive NVD coverage.
- Kept collection manual and local use unchanged. No composite risk score, scanner, automatic refresh or public deployment.

## P0.1 — International stable — 2026-10-26 — stable main baseline

- Added English/French application labels and locale-aware formatting, with local preference and no remote translation service.
- Preserved original CISA texts, identifiers, source values and navigation/filter state during language switching.
- Recorded validation: **59 backend**, **46 frontend**, **8 operations tests** (also 8 under optimized Python), and successful frontend build.
- Stable reference: **`p0.1-international-stable`**. CISA KEV remains the only cyber data connector in this milestone.

## P0 — NIGHTFALL ALPHA 007 — 2026-10-26 — initial local milestone

- Delivered the local CISA KEV overview, searchable catalogue, CVE inspector and data-control views using React/TypeScript, FastAPI and SQLite.
- Added validated manual source import, provenance, last-valid-data retention, local backup and foreground startup/shutdown.
- Recorded validation: **59 backend**, **27 frontend**, **8 operations tests** (also 8 under optimized Python), and successful frontend build.
- Charts represent catalogue additions, not attacks; no device-vulnerability inference or general legal-duty claim.

**Français :** les premiers jalons décrivent leur périmètre historique. La première Alpha intègre P0.1 et P1-A ; le tag P0.1 reste figé. Les anciens résultats et comptes de sources sont datés, pas des garanties de recette R1.
