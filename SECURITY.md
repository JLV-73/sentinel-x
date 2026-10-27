# Security policy

SENTINEL X is intended for private, single-user, local defensive use. Servers bind only to **127.0.0.1** (API **8007**, frontend **5177**). This is not an authorization for public hosting, remote access, scanning or exploitation. No security certification or fixed support/response commitment is claimed.

## Report privately

**Do not report a suspected vulnerability in an ordinary issue, pull request, public discussion or public code comment.** Do not upload secrets, credentials, personal information, private computer paths, private audit material, databases, raw source files or unredacted logs/screenshots there, even while the repository is private.

1. If GitHub offers **“Report a vulnerability”** for this repository, use its private reporting/advisory flow. Confirm that the destination is private before submitting; availability is not assumed.
2. Otherwise contact **@JLV-73 through an already established private owner channel**. This policy does not designate a public profile comment, a new inbox or a monitored email address as that channel.
3. If neither option is available to you, do not disclose details in an ordinary issue. Wait until a private contact route is established with the owner. No public onboarding or public-report handling service is currently offered.

Share only the affected milestone/branch, a brief impact description, sanitized reproduction steps and the minimum evidence needed. Do not send tokens or complete database/raw-source dumps. Agree a private transfer method with the owner before any necessary sensitive evidence is shared. If a credential was exposed, use its provider's authorized revocation/rotation process; do not reproduce it in the report.

Do not probe third-party systems or other users' installations. Reproduce only in a disposable local instance with synthetic fixtures and explicit authorization. Live collection requires a separate deliberate action and is not a security test.

## Triage and disclosure

The owner decides investigation, remediation and any coordinated disclosure. There is no promised acknowledgment time, fix deadline, bounty or public disclosure date. P0.1 is the stable baseline; P1-A is development. Neither designation establishes a supported-version matrix or an SLA. Updates, releases and visibility changes require explicit JLV authorization.

## Safe ordinary bug reports

Only non-sensitive functional bugs belong in the bug-report form. Remove private paths, usernames, tokens, raw payloads and identifying metadata before sharing a minimal example. If uncertain whether the issue is security-sensitive, use the private route above.

**Français :** ne jamais déposer une vulnérabilité, un secret, un chemin privé ou une base dans les Issues/PR. Utiliser le signalement privé GitHub s'il est proposé ; sinon le canal privé déjà établi avec JLV. À défaut, attendre un canal privé, sans publier les détails. Aucun délai de réponse ni service de signalement public n'est promis.
