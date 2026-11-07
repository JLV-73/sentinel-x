# v0.2.0 — proposed notes, local candidate

**Documentation draft: no tag or publication performed.** `VERSION` and frontend package metadata identify 0.2.0. Release status and distribution remain subject to decision; this text asserts no current remote availability.

## Scope and maturity

| Area | State observed in source | Limits |
|---|---|---|
| NIGHTFALL CISA KEV, NVD/CVSS, EPSS and triage | Existing local features | Explicit collection; separate data and signals, no invented risk score or device diagnosis. |
| GHSA | Existing bounded pilot | Explicit lookup for one local CVE, one page and at most 100 advisories; coverage is incomplete. |
| DIGITAL FORTRESS fixture | Experimental | Loopback HTTPS; simulated DNS and public peer; three predetermined scenarios, no Internet site. |
| JSON import and HTML report | Experimental | Manual local import, closed validation, preview and export; declared, unauthenticated observations. |
| Internet site analysis | Disabled, safeguards unqualified | No launch even with URL and authorization; no real-target audit. |

Details and use: [local guide](DIGITAL_FORTRESS_LOCAL.md), [import contract](diagnostic-import-schema.md), [GHSA contract](GHSA_PILOT_CONTRACT.md). Demo and import do not contact the Internet; installation and official-source collection are separate and may need it. No certification, production readiness or suitability for public exposure is promised. Existing safeguards remain necessary; no user target was contacted to prepare these notes.

## Verification and proposed publication path

These notes are based on static source and document review; they assert no newly executed tests, browser acceptance or source collection. Historical evidence is not acceptance testing of this candidate.

Proposed sequence, not to be executed without separate authorization:
1. Review the exact scope, licenses and excluded data; obtain independent validation and suitable acceptance checks in an isolated environment without enabling Internet analysis.
2. Review version metadata and decide the exact commit/tree and pre-release versus stable status separately; resolve discrepancies before deciding. Do not move existing tags or touch operational copies and data.
3. Only after explicit GO, prepare an immutable tag and source-only Release; explicitly decide its status and any distribution. Exclude binaries, databases, backups, secrets and private evidence. Retain LICENSE, NOTICE and third-party rights.
4. Verify the actually published tag, tree, archives and visibility. Without GO, retain only the local candidate; even a remote draft is a separate action.
