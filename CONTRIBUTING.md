# Contributing to SENTINEL X

SENTINEL X is a private JLV LABS project. These rules are for contributors explicitly authorized by the owner; they do not open public onboarding, invite collaborators or grant source-code rights. English is the shared documentation language; French reports and discussion are welcome.

## Before proposing a change

- Read the README for the target branch, [Security policy](SECURITY.md) and [Code of conduct](CODE_OF_CONDUCT.md).
- `main` is the stable **P0.1** baseline. **P1-A** development belongs on `p1/intelligence-core`; do not introduce its source connectors into stable `main` by default.
- Agree the scope with **@JLV-73** before architectural, dependency, source-collection or data-storage changes. Do not work directly on `main`.
- Use sanitized, minimal examples. Never attach credentials, personal or private computer paths, databases, raw source archives, private audit material or unredacted logs/screenshots to an issue or PR. Security findings follow `SECURITY.md`, not the ordinary issue forms.

## Pull requests and review

All proposed changes go through a pull request to the agreed target branch, with local test evidence and owner review before acceptance. Include the purpose, affected milestone, changes, limitations, test commands/results and a rollback or recovery note where relevant. Keep unrelated work separate. Document tests that were not run and why; do not substitute a historical result for a current run.

**@JLV-73 retains the merge decision.** A structural merge, including integration of P1 into stable `main`, a release, or any visibility change requires an explicit **JLV GO**. A PR, review request or green test result is not that authorization. This policy and `CODEOWNERS` express review intent; they do not claim GitHub branch protection, rulesets or enforced approvals are configured. Enforcement availability can depend on the account plan and private-repository settings.

## Local validation

Use the branch's project-local environment and committed lockfiles (`backend/requirements-lock.txt`, `frontend/package-lock.json`). Install only when deliberately setting up the checkout; do not upgrade dependencies implicitly or reuse another application's environment. From the checkout root, in PowerShell:

```powershell
.\.venv\Scripts\python.exe -I -m pytest backend\tests -q
.\.venv\Scripts\python.exe -I -m unittest discover -s scripts -p "test*.py" -v
.\.venv\Scripts\python.exe -I -O -m unittest discover -s scripts -p "test*.py" -v
.\.venv\Scripts\python.exe -I -m unittest discover -s tools -p "test*.py" -v
npm --prefix frontend test -- --maxWorkers=1
npm --prefix frontend run build
```

Run these local checks before requesting acceptance of a PR and record their actual results. If a check cannot be run, identify the blocker and keep the PR unready for acceptance; an explanation alone does not satisfy the validation gate. For documentation changes, also validate links, commands, branch accuracy and sensitive-content exclusions. Keep FR/EN functionality equivalent, command blocks identical and official source texts unchanged. Exercise a relevant regression for every bug fix.

The standard unit suites use isolated test data; live browser recipes and source-collection scripts are **not** ordinary offline tests. Do not run them without specific approval and a verified isolated target. A startup must not collect sources or open a browser automatically. Both servers stay on **127.0.0.1**, backend **8007**, frontend **5177**. Never stop unrelated processes to free a port.

## Boundaries

No default external writes, public exposure, remote access, new paid service, Actions workflow, automated source refresh, invitations, profile changes, scans or exploitation are authorized by this policy. Do not commit runtime data, virtual environments, caches, dependencies or secrets.

No project license has been selected and no open-source grant or contributor license agreement is established here. Submit only material you are authorized to share privately. Any necessary rights arrangement must be agreed with the owner before acceptance; a PR does not settle licensing. Third-party code and data retain their own terms, separately from JLV LABS original code.

**Français :** contributions uniquement sur autorisation, par PR vers la branche convenue, avec tests locaux et revue du propriétaire. Toute fusion structurante, publication de version ou modification de visibilité exige un GO explicite de JLV. Aucun droit de réutilisation n'est accordé par ce document.
