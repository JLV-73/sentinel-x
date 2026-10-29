# Third-party materials and obligations

Original project code owned by JLV LABS is Apache-2.0; see `LICENSE`, `NOTICE`
and `COPYRIGHT.md`. That grant does not relicense external software or data.

Dependency lockfiles record exact versions; `docs/DEPENDENCY_LICENSES.json`
records all audited declarations and their evidence levels. Dependencies are
installed locally, not vendored in this source repository. Preserve their actual
licenses, NOTICE files, attribution and any covered-source obligations when
creating a binary, bundle or commercial distribution.

Selected runtime notices are copied verbatim under `third_party/software/`:
React/React DOM (MIT), ECharts (Apache-2.0 and incorporated BSD d3 notices),
ZRender (BSD-3-Clause), Lucide (ISC and MIT Feather-derived icon terms).

Additional important obligations: certifi/lightningcss (MPL-2.0), caniuse-lite
(CC-BY-4.0 attribution). Optional platform lock entries and three installed
metadata-only packages are documented as incomplete evidence, not silently
claimed cleared. See `docs/LICENSE_OPTIONS.md` for the release gate.

## CISA KEV

The official upstream notice for the database is reproduced verbatim at
`third_party/cisa/UPSTREAM-NOTICE.txt`: CC0 1.0, with no permission to use the CISA
logo or DHS seal and no implied endorsement. The app-only CISA overview screenshot
has been reviewed for visible private data; no CISA logo/DHS seal is reproduced.
The screenshot is a dated demonstration of authentic public CISA information,
not a live feed or proof of user-device vulnerability.

The validation schema is not transferred: its separate scope is uncertain. Install
the pinned official resource locally using `tools/bootstrap_schema.py`; see
`docs/SCHEMA_SETUP.md`. Its bytes remain identical to the tested historical schema.

## NVD and FIRST EPSS — integrated Alpha

No raw replies, dumps, runtime histories or NVD/EPSS screenshots are distributed.
Official NVD terms could not be fully retrieved with verified TLS during this
audit; no unrestricted redistribution clearance is asserted.

FIRST confirms free EPSS lookup and asks for EPSS attribution, but this does not
establish unrestricted dataset relicensing or unrestricted bulk API use. The
current development application refreshes targeted local KEV identifiers; future
scale must stay within current provider policies. Read `docs/SOURCES.md` before
planning data redistribution or commercial packaging.

NVD attribution: "This product uses data from the NVD API but is not endorsed or
certified by the NVD."

## GitHub Advisory Database — P1-C pilot

Advisory data: **GitHub Advisory Database and its contributors**, licensed under
[Creative Commons Attribution 4.0 International (CC-BY-4.0)](https://creativecommons.org/licenses/by/4.0/).
Source: <https://github.com/advisories>; upstream license:
<https://github.com/github/advisory-database/blob/main/LICENSE.md>.

The app explicitly retrieves reviewed public records from the official GitHub REST
API, retains the original JSON with request URL/date/SHA-256, and projects selected
fields with local availability/freshness/cache metadata. Those projections and local
metadata are application processing, not new source statements or GitHub endorsement.
Original descriptions, identifiers, ranges, dates and severity declarations are not
translated or recomputed. Runtime caches are not bundled with the source repository;
offline synthetic test fixtures are identified as such. The genuine offline fixture
`frontend/src/components/fixtures/ghsa-official-log4shell.json` is an unmodified
anonymous API response retrieved on 2026-10-28 from
<https://api.github.com/advisories?cve_id=CVE-2021-44228&type=reviewed&per_page=100>;
it retains its source credits and is covered by the same CC-BY-4.0 attribution,
not the project code license. Real advisory excerpts visible
in dated pilot screenshots keep the source/CC-BY-4.0 attribution and do not establish
user-device exposure. The Apache-2.0 project license does **not** relicense these data.
