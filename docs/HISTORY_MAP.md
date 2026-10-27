# Sanitized publication history

This repository has a deliberately new Git history. The original local project
history contained private workstation/operational evidence and was not uploaded.
The original history, branches and tag remain intact in the private local archive.

| Original source reference | Clean publication reference | Meaning |
|---|---|---|
| `595fc494068d4a3b9991e93cc76c69927dca4bb3` | `main` / `p0.1-international-stable` | P0.1 source snapshot plus publication documentation |
| `cbab06febc7ec69f5bde18d86d5f5811bc4742c9` | `p1/intelligence-core` | P1-A source snapshot plus publication documentation |

The original and publication commit IDs are intentionally different. Backend,
frontend source, application tests, dependency locks and selected portable
operational scripts are copied byte-for-byte from the stated source references.
Documentation and Git packaging are prepared for this separate repository.

No P1-A application code is merged into main. The clean P1-A branch starts from
the clean P0.1 publication snapshot, preserving the stable/development boundary.
The sole runtime validation resource is not redistributed: a pinned, SHA-256
verified installer retrieves the exact historical schema bytes locally. This is
an explicit external prerequisite, not a modification of the collectors or UI.

Excluded: local databases/backups/environments/node_modules, raw response caches,
internal JSON/log reports, workstation-specific browser recipes, private audit
helpers and machine paths. Only an app-only CISA overview screenshot is selected;
no unreviewed raw catalogue or EPSS/NVD dump is transferred.

A private verification record maps the actual publication commit IDs and records
full-history audits and file hashes. Original private audit material is not
embedded in this publication history.

## G2 public-source launch

G2 adds documentation/license-only descendants on each branch; no application
source merge is performed. The immutable stable tag retains its G1 target.
Apache-2.0 now covers JLV-owned original code also in the earlier clean snapshots;
old pending-license wording describes the prior decision state. See COPYRIGHT.md
and NOTICE at the current branch root. Original private local history is never
uploaded; only the already-sanitized publication history becomes public.
