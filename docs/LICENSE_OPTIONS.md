# License options — Product Owner decision pending

No definitive SENTINEL X license is selected. Original-code rights remain reserved
by default; this private repository is not an open-source grant. This is a
technical decision brief, not a full legal opinion or ownership due diligence.

| Option | Reuse / commercial activity | Contributions and redistribution |
|---|---|---|
| MIT | Broad reuse, modification and sale, including closed derivatives | Preserve copyright/license notice; simple, but no express contributor patent grant |
| Apache-2.0 | Broad reuse and commercial/closed derivatives | Preserve license and relevant NOTICE/attribution; mark modifications; express contributor patent grant and patent-termination provisions |
| GPLv3 | Commercial use and sales allowed; distributed derivatives generally keep strong copyleft | Corresponding source and GPLv3 terms for covered distributions; ordinary private use does not itself require publication |
| AGPLv3 | Commercial activity allowed; stronger reciprocity including covered remote-network use | GPL-like duties plus source offer to interacting users for modified covered network software; may deter proprietary integrations |

**Recommendation for a later JLV decision:** Apache-2.0 best matches an
international reusable/commercial engineering base with express patent terms.
MIT is simpler but less explicit on patents. GPLv3/AGPLv3 make sense if reciprocal
source availability becomes the business objective; neither forbids selling.

A permissive license cannot by itself reserve an exclusive right to commercialize
released original code. A future dual-license strategy requires control of the
relevant copyrights and compatible contributor grants; do not assume that
maintainer status or receiving a PR transfers ownership.

Before public onboarding, JLV must decide project license, contributor inbound
terms (DCO/CLA or another reviewed process), ownership/patent due diligence,
trademark policy and commercial model. Contributors retain third-party terms;
no blanket relicensing of dependencies or data is implied.

## Dependency constraints actually audited

- Python: 28 locked packages, six direct, 22 transitive; matching installed
  versions and local license evidence for all 28.
- npm: 228 lock entries / 225 unique name-version pairs; 18 direct entries.
  184 installed entries match; 44 optional platform entries have lock-only
  evidence. Three installed entries lack separate local license files:
  `@rolldown/binding-win32-x64-msvc`, `dlv`, `saxes`.
- No declared GPL/AGPL package license was found. This does not clear every
  embedded tool/binary or every possible combination of future project terms.
- MPL-2.0: certifi and lightningcss/platform bindings need file-level source/notice
  compliance when redistributing covered code. This does not automatically force
  all independent application files under MPL.
- CC-BY-4.0: caniuse-lite requires attribution when applicable; ECharts Apache
  NOTICE/BSD d3 terms and Lucide ISC plus MIT Feather-derived terms must survive.
- Apache-2.0 is not GPLv2-only compatible; GPLv3/AGPLv3 combinations and bundled
  components require a concrete distribution review, not a blanket matrix claim.

Full names/versions/declarations and evidence levels are listed in
`DEPENDENCY_LICENSES.json`; selected runtime notices are under `third_party/`.
No dependency tree, binary bundle, raw NVD/EPSS data or runtime database is shipped.
Schema redistribution is intentionally avoided with a pinned local installation
resource (see `SCHEMA_SETUP.md`). Public/packaged redistribution remains a later
gate: resolve incomplete license evidence, applicable terms and source/notice
obligations for exactly what will be distributed.
