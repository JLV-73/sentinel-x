# License decision — Apache-2.0

JLV selected Apache License, Version 2.0 on 2026-10-27 for original project code
in which JLV LABS holds rights. See `../LICENSE`, `../NOTICE`, `../COPYRIGHT.md`.
This supersedes G1's pending decision without rewriting historical references.

The original technical comparison favored Apache-2.0 for permissive reuse,
commercial/closed derivatives and express patent terms, with license/NOTICE and
change-marking duties. MIT is simpler without express patent language. GPLv3
strong copyleft and AGPLv3 network-related duties were considered, not selected.
Commercial use is not prohibited by any of those options. Apache-2.0 does not
reserve exclusive commercialization rights or override third-party licenses.

Contributions intentionally submitted for inclusion follow Apache-2.0 section 5;
contributors retain ownership. No extra CLA or copyright assignment is imposed.
This is a scoped project-owner decision, not an independent legal title opinion.

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
resource (see `SCHEMA_SETUP.md`). The optional dependency entries and binaries are not distributed by this source
publication. A future package/binary/dataset distribution must resolve its actual
license evidence, source/notice obligations and provider terms separately.
