# Verification of publication snapshots

These results were actually executed on the clean source snapshots prepared for
private transfer, using the existing pinned project-local dependencies. No new
global installation, source refresh, browser session or TCP server was launched
for GitHub Foundation. Snapshot tests use isolated runtime fixtures.

| Edition | Backend | Operations | Frontend | TypeScript + Vite build |
|---|---:|---:|---:|---|
| P0.1 stable | 59 PASS | 8 PASS | 46 PASS / 7 files | PASS |
| P1-A development | 217 PASS | 9 PASS | 74 PASS / 11 files | PASS |

A first combined test runner timed out; completed results were preserved and the
remaining edition rerun successfully. Final tables use completed runs, not a
success assumption from the timeout.

Common warnings: Starlette/AnyIO deprecation and a minified frontend chunk above
500 kB. No warning was suppressed to claim a clean test run. No new application
regression was found.

The new schema installer has four isolated test methods per checkout: byte-exact
installation/no-network reuse, rejection of incorrect downloads, preservation of
an existing different file, and slow-progress budget exhaustion (with and without
read1). They passed in all three preparation trees, totaling 12 test executions.
The independent review initially rejected a missing total-download budget; the
correction adds a cooperative monotonic budget, not an absolute wall-clock cap.
Real verified-TLS retrieval of the pinned revision also
succeeded and matched SHA-256
`0d5865c98694c5bfba2c78a26caf814f406b3fce8bfb81bef79e99c7f288b0e7`.
The resource remains ignored and is never uploaded.

Before transfer, selected source-file hashes are compared to the original
P0.1/P1-A commits. Application Python/TypeScript/CSS and lockfiles are unchanged.
Git packaging/documents and the external-resource bootstrap are the changes.
The original repository history, refs, administrative files, tracked files and
operational data are checked separately and preserved.

Publication-history audit checks every reachable commit/blob, private paths,
credentials/provider-token patterns, binary allowlist and prohibited runtime
artifacts. Positive test literals and upstream copyright contact addresses are
reviewed contextually; no secret claim is based on a substring scan alone.

Historical browser recipes and logs are not uploaded because they carried
workstation-specific context. The selected screenshot came from the real
application validation; its visible pixels and PNG metadata were reviewed for
private content. It is not a new browser run or generated concept art.

Remote completion requires reading GitHub metadata, exact branch/tag targets,
file trees and a fresh clone, then checking privacy and the absence of releases,
Pages, Actions workflows/runs and unintended collaborators. Private detailed
records are retained outside this repository rather than leaking local paths.
