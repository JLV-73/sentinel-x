# DIGITAL FORTRESS — v0.2.2 candidate

[Français](DIGITAL_FORTRESS_V022.fr.md) · [README](../README.md)

This is an experimental local Windows source candidate, not a published release, a complete audit, a security certification or a production-readiness claim. The [local guide](DIGITAL_FORTRESS_LOCAL.md) describes the fixture and import separately.

## Scope

The candidate offers an explicit HTTPS **HEAD observation attempt** for one entered URL: at most one HTTP request per attempt, with no retries or followed 3xx redirects. A refusal or failure before sending means no HEAD may have been sent. It is neither a vulnerability scanner nor an exploitation attempt. An HTTP response, a successful handshake or the mere presence of a security header does not establish security or header compliance. Incomplete, blocked or failed observations must not be interpreted as a clean result.

Only attempt an observation with explicit authorization covering the exact target, path, method and timing. Consent in the interface is a declaration, not independent proof of authority. The path and query are sent to the local service and target; the displayed result masks them. Avoid secrets in URLs. Do not expose the local application publicly.

## Safeguards and limits

- The transport validates HTTPS destinations and DNS answers, rejects private and other special addresses, connects to a checked address and compares the connected peer. This SSRF mitigation deliberately excludes some public transition or relay addresses; it is not a proof against every network or deployment scenario.
- TLS uses the system trust roots and checks the certificate and hostname. A verified handshake does not certify the site, its content, or the security of its configuration. TLS/transport failure may have multiple causes; do not infer an invalid certificate without evidence.
- The UI's cancellation or navigation does **not** propagate cancellation to the worker. A supervised deadline is intended to limit execution, but it is not an absolute real-time guarantee.
- Cleanup after parent crashes is only partially qualified; cross-session exclusion has not been demonstrated. A named mutex is not proof of its permissions or isolation across sessions and identities. Do not assume either guarantee or production readiness.
- The local fixture and imported reports remain separate from real observations: the fixture is synthetic; imported observations are user-declared, not independently authenticated. No local fixture or mock proves Internet transport behavior.

No network observation is performed by reading this document. Remote availability of a v0.2.2 tag or release is not established by the candidate's metadata.
