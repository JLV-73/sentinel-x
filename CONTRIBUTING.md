# Contribute to SENTINEL X

**Fork → Clone → Branch → Changes → Tests → Pull Request.**

SENTINEL X is an experimental defensive open-source JLV LABS project under
Apache-2.0. English is the shared documentation language; French is welcome.
Opening a PR grants neither write access nor authority to merge or publish a release.

## 1. Choose the target, then create your branch

- `main`: stable **P0.1 INTERNATIONAL EDITION**, CISA KEV only.
- `p1/intelligence-core`: experimental **P1-A INTELLIGENCE CORE**, adding NVD/CVSS
  and FIRST EPSS; not merged into stable main.

Use GitHub's **Fork** button on [the repository](https://github.com/JLV-73/sentinel-x).
Replace `YOUR-GITHUB-LOGIN` below with your actual GitHub login. In a normal,
non-administrator PowerShell window (choose another unused folder name if needed):

```powershell
Set-Location $HOME
git clone https://github.com/YOUR-GITHUB-LOGIN/sentinel-x.git sentinel-x-contrib
if ($LASTEXITCODE -ne 0) { throw "Clone failed. Stop here." }
Set-Location .\sentinel-x-contrib
git remote add upstream https://github.com/JLV-73/sentinel-x.git
git fetch upstream
git switch -c docs/describe-change upstream/main
```

For a P1-A change, branch from `upstream/p1/intelligence-core` instead of
`upstream/main` and target `p1/intelligence-core` in the PR. Do not develop directly
on either upstream base. Follow the README's prerequisites and local dependency
steps from your clone root; do not clone a second time or reuse another app's venv.

## 2. Make focused, safe changes

Agree architectural, dependency, source-collection or storage changes with
**@JLV-73** first. Preserve FR/EN equivalence, official source texts and identifiers.
Do not attach credentials, personal paths, databases, raw source dumps, private
audit material or unredacted logs/screenshots. Security issues follow
[SECURITY.md](SECURITY.md), never an ordinary public issue/PR. See also
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## 3. Validate the change actually made

Use committed lockfiles and the checkout's own environment. No implicit upgrade.

**Documentation-only PR:** check commands, links, branch/version accuracy, FR/EN
parity and privacy; exercise the relevant installation steps where feasible.
A full application regression campaign is not required for unchanged application
code. State exactly what was run, what was not run, and any real blocker.

**Application/script changes:** run the relevant regression and local suites from
the root (plus any additional checks justified by the change):

```powershell
.\.venv\Scripts\python.exe -I -m pytest backend/tests -q
.\.venv\Scripts\python.exe -I -m unittest discover -s scripts -p "test*.py" -v
.\.venv\Scripts\python.exe -I -O -m unittest discover -s scripts -p "test*.py" -v
.\.venv\Scripts\python.exe -I -m unittest discover -s tools -p "test*.py" -v
npm.cmd --prefix frontend test -- --maxWorkers=1
npm.cmd --prefix frontend run build
```

These unit tests use isolated fixtures. Live browser recipes and source collection
need a deliberate authorized action and a verified isolated target. Both servers
stay on **127.0.0.1** (API 8007, frontend 5177). Never stop unrelated processes to
free a port. Startup must not automatically collect sources or open a browser.

## 4. Push to your fork and open a PR

```powershell
git add README.md README.fr.md CONTRIBUTING.md
git commit -m "docs: clarify installation"
git push -u origin docs/describe-change
```

The file list and branch name above are an example for a documentation change;
stage only your intended files. Open GitHub's **Compare & pull request**, select
`JLV-73/sentinel-x` and the agreed base branch, and describe purpose, changed files,
test commands/results, limitations and recovery notes. Do not include secrets or
private evidence. Keep the PR unmerged until reviewed and approved.

## Current protection and decision rules

At D1 verification (2026-10-27), **main is technically protected**: ordinary changes
require a PR, **one approval**, and a **CODEOWNERS review**; stale approvals are
dismissed, conversations must be resolved, and force-push/deletion are blocked for
users subject to the protection. **JLV's administrator exception remains available**
for administration, not as permission to bypass the project's GO decisions.

**P1-A is not protected at this verification.** It does not inherit main's rules;
this is not a promise of identical enforcement. Nevertheless all proposed P1-A
changes also follow the documented PR/review/test process.

**GitHub Actions is disabled.** There is no required hosted CI workflow. Do not
enable automation or add paid services to make a PR appear validated.

**@JLV-73 retains the merge decision.** Structural merges (including P1 into main),
releases and visibility changes need explicit JLV GO. A PR or green check is not
that authorization. No scan, exploitation, external operational write, public
hosting, automated refresh or invitation is authorized by this document.

## Contribution license

Contributions intentionally submitted for inclusion follow Apache License 2.0
section 5, unless explicitly stated otherwise. Submit only material you can
contribute; identify third-party terms/notices. Contributors retain ownership.
**No additional CLA, copyright assignment or formal DCO sign-off is imposed.**

**Français :** fork, clone, branche, modifications, tests ciblés puis PR vers la
bonne base. Main est protégée ; P1-A ne possède pas la même protection. Revue et
validation avant toute intégration. Actions désactivé ; aucune fusion automatique.
Contributions sous Apache-2.0, sans cession ni CLA additionnel.
