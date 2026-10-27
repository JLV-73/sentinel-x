# OSV / GitHub Security Advisories — SENTINEL X P1-B study

**Checked: 27 October 2026 (UTC).** Documentary study and two public reads only; no connector, dependency scan, authentication setup or application test.

## Synthèse et recommandation

**Priorité réelle : consolider le triage CISA/KEV + NVD + EPSS existant (probabilité à 30 jours et percentile), pas ajouter deux flux.** Sans inventaire/SBOM, SENTINEL X ne peut pas déclarer un PC vulnérable. Sous **nouveau GO**, privilégier un petit pilote GHSA *reviewed*, relié aux CVE déjà suivies ; évaluer ensuite OSV pour élargir la couverture, avec licences autorisées explicitement. Aucun pilote n'est implémenté ici.

## Coverage and package precision

**OSV.dev** aggregates ecosystem databases, including GitHub Advisory Database, Go, PyPI, RustSec, OSS-Fuzz and distribution sources; it also converts selected NVD open-source CVEs.[1] Its documented coverage spans language registries, Linux distributions, Android and Git/C/C++; this is broader source diversity, not evidence of complete coverage.[1]

**GitHub Advisory Database** publishes OSV-format JSON and distinguishes reviewed vulnerabilities, unreviewed NVD imports and malware.[5] Reviewed advisories receive validity, description, ecosystem and package checks; supported registries include npm, Pip, Maven, NuGet, Composer, Go, Rust, RubyGems, Erlang, Pub, Swift and GitHub Actions.[5] Unreviewed does not mean confirmed invalid; it means GitHub has not checked validity/completeness.[5]

OSV identifies packages by **ecosystem + name**, optionally PURL, and expresses affected versions through explicit lists or typed ranges with introduction/fix boundaries.[2] GitHub REST exposes package/ecosystem, `vulnerable_version_range` and nullable `first_patched_version`; one advisory can describe several package/range entries.[6][15] Neither substitutes for an accurate installed-version inventory.

## Identifiers, overlap and provenance

Each GitHub advisory has a GHSA ID; retain its CVE when supplied, rather than requiring one for every advisory.[5][6] OSV's `aliases` means the **same vulnerability**; `upstream` describes supply-chain relationships and `related` can describe different vulnerabilities.[2] Recommendation: preserve original IDs, source and relationships; never collapse `related` or `upstream` into CVE aliases.

GitHub imports NVD; OSV imports GitHub and converts some NVD records, so these are **overlapping, not independent confirmations**.[1][5]
CISA's separate KEV catalog supplies the known-exploitation dimension.[12]
Keep KEV status, NVD enrichment and FIRST EPSS separate from package advisory severity.
GitHub also republishes FIRST EPSS, with daily synchronization and percentiles updated only when significantly different; retaining the existing direct EPSS source avoids a redundant signal.[5]

## Access and operational rules

OSV documents `POST /v1/query`, `POST /v1/querybatch` and `GET /v1/vulns/{id}`; public GET worked without a key.[3][14] POST query is a lookup, not publication; no POST was exercised. OSV currently documents **no API rate limit**, but an HTTP/1.1 response-size ceiling of **32 MiB**; do not interpret this as unlimited service capacity or a contractual entitlement.[3]

GitHub global REST provides `GET /advisories` and `GET /advisories/{ghsa_id}`, permits unauthenticated public reads, and filters by CVE, GHSA, ecosystem, affected package/version and modification dates.[6]
Defaults return reviewed non-malware advisories; pagination has a maximum of 100 records/page.[6]
The documented anonymous allowance is **60 requests/hour per originating IP**; authenticated user requests generally share 5,000/hour, but no credentials were created or used.[7]
Secondary limits also apply: honor rate headers, `Retry-After`, reset times and backoff on 403/429.[7]

## Rights are not interchangeable

The **OSV schema**, **OSV.dev infrastructure code** and **OSV-Scanner tool** carry Apache-2.0 licenses in their respective repositories; these are not blanket licenses for aggregated vulnerability records.[9][10][11]
GitHub Advisory Database data is **CC-BY-4.0**: preserve supplied attribution/license notices and indicate modifications.[8]

OSV lists heterogeneous upstream terms, including CC0, CC-BY, Ubuntu/Alpine CC-BY-SA and Chainguard/Wolfi CC-BY-NC-ND.[1] Its ingestion policy recommends permissive licensing but does not erase upstream conditions.[13] Recommendation: assess licenses per selected source/record and retain attribution; do not claim commercial redistribution clearance for the whole aggregate.

## Freshness, verified reads and limits

OSV exposes `published`, `modified`, withdrawal and source attribution; enrichment/alias recomputation can change `modified` without a newly disclosed flaw.[2][13]
Its freshness target is sources no more than 15 minutes stale, 99.5% of the time—an **SLO**, not measured end-to-end disclosure freshness here.[4]
Withdrawn records remain accessible by ID/export but are excluded from POST queries; upstream deletions from Git/REST can currently leave orphaned valid records.[4]

GitHub exposes publication, update, review, NVD-publication and withdrawal timestamps; no general advisory import-delay guarantee was established.[6]

At **16:24 UTC**, both unauthenticated GETs for `GHSA-jfh8-c2jp-5v3q` returned **200**, linked `CVE-2021-44228`, and contained ten affected package/range entries—not ten vulnerabilities.[14][15]
OSV identified GitHub as its source; its `modified` was `2025-10-22T19:37:02.616807Z`, versus GitHub `updated_at` `2025-10-22T19:13:26Z`.[14][15]
Historical fix boundaries are not current upgrade recommendations.

Raw responses, headers, UTC retrieval times, SHA-256 hashes and verbatim citation evidence are retained privately under `evidence/osv-ghsa/` and `osv-ghsa-citations.json`. NVD's reference page failed certificate validation, then returned 403 through verified-TLS curl; overlap conclusions instead use retrieved OSV/GitHub documentation. No coverage percentage, sustained quota capacity, application behavior or asset exposure was tested.

**Future pilot acceptance, under separate GO:** public fixtures only; deterministic CVE/GHSA deduplication; package-name/version semantics; null and withdrawn handling; source timestamps, licensing and attribution; cached bounded reads and failure isolation. Adopt only if it adds useful remediation context beyond the existing three sources.

## Sources

[1] https://google.github.io/osv.dev/data — osv-data
[2] https://ossf.github.io/osv-schema — osv-schema
[3] https://google.github.io/osv.dev/api — osv-api
[4] https://google.github.io/osv.dev/faq — osv-faq
[5] https://docs.github.com/en/code-security/concepts/vulnerability-reporting-and-management/github-advisory-database — gh-overview
[6] https://docs.github.com/en/rest/security-advisories/global-advisories — gh-rest
[7] https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api — gh-rates
[8] https://raw.githubusercontent.com/github/advisory-database/main/LICENSE.md — gh-data-license
[9] https://raw.githubusercontent.com/google/osv.dev/master/LICENSE — osv-code-license
[10] https://raw.githubusercontent.com/ossf/osv-schema/main/LICENSE — osv-schema-license
[11] https://raw.githubusercontent.com/google/osv-scanner/main/LICENSE — osv-scanner-license
[12] https://raw.githubusercontent.com/cisagov/kev-data/main/README.md — cisa-kev
[13] https://google.github.io/osv.dev/data/new — osv-new-data-corrected
[14] https://api.osv.dev/v1/vulns/GHSA-jfh8-c2jp-5v3q — osv-public-read
[15] https://api.github.com/advisories/GHSA-jfh8-c2jp-5v3q — gh-public-read
