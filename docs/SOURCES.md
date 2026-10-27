# Official sources and interpretation

## CISA KEV foundation

Canonical JSON: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

Official mirror: https://github.com/cisagov/kev-data

Known exploitation is not proof that a particular user's equipment is vulnerable.
Catalogue-addition graphs are not attack timelines. Published CISA due dates are
not general French legal deadlines. Missing ransomware evidence is not proof of
absence. Source texts and identifiers remain unchanged.

The upstream KEV repository's license declares CC0 1.0 for the database, excludes
rights to use the CISA logo/DHS seal and disclaims endorsement. The ancillary
validation schema's licensing scope remains uncertain: its bytes are deliberately
not transferred in Git. Installation retrieves the pinned official resource locally
and checks its SHA-256; see `SCHEMA_SETUP.md` and `config/kev-schema.source.json`.
The selected screenshot shows only the application's CC0 CISA overview; it is not
a raw catalogue redistribution. Third-party links have their own terms.

## NVD and FIRST EPSS — integrated P1-A enrichment

NVD API: https://services.nvd.nist.gov/rest/json/cves/2.0

NVD documentation: https://nvd.nist.gov/developers/vulnerabilities

NVD policy: https://nvd.nist.gov/developers/start-here

FIRST API: https://api.first.org/data/v1/epss

FIRST documentation: https://api.first.org/epss/

CVSS is technical severity, with its original version, vector and metric provider.
EPSS is an estimated 30-day exploitation probability; percentile is relative rank.
Neither is a personal risk score. API version is not an EPSS model-version claim.

Collection is manual and targeted, with persistent source pacing, bounded reads,
transactional cache updates and explicit freshness/error/absence states. The
NVD `cveId` parameter worked in the delivery tests but is documented as deprecated;
a future provider change may require an approved compatibility update. NVD
policy verification included official-page indexed excerpts when developer pages
returned 403; no access protection was bypassed.

NVD attribution remains visible in the UI: "This product uses data
from the NVD API but is not endorsed or certified by the NVD."

No raw CISA/NVD/EPSS downloads or local collection histories are shipped here.
Consult current provider terms before redistributing derived datasets or building
a commercial packaged distribution. See `THIRD_PARTY_NOTICES.md`.
