# DIGITAL FORTRESS — P2 safety and audit contract (draft implementation)

P2 development only, base v0.1.1; no P2 merge, tag or release. Audit of any
external site needs a separate target-specific owner authorization. No site is
implicitly authorized by installation or by this project GO.

## Explicit scope, resource limits and communication

User supplies one primary HTTP(S) URL on port 80/443, at most three additional
manually specified URLs on the same exact origin, optional explicitly named query
parameters per route, level standard/deep and explicit authorization confirmation.
Reject credentials, fragments, ambiguous URL forms, control characters, mismatched
origins, IP literals where policy cannot prove public unicast, paths outside the
submitted allowlist, and dangerous/credential-like query parameters. Unknown/invalid
input fails before DNS/HTTP. Only GET, HEAD and OPTIONS; no forms, authentication,
user cookies, proxies, files, brute force, network scan, crawl, fuzzing or retries.
No startup/GET-side audit. Sequential requests, global hard budget 30 total including
redirect hops, per-audit bounded elapsed time and response size; stop immediately
on 401/403/429 or security blocks and unexpected behavior. Do not claim absolute
deadlines if blocking resolver/socket calls can exceed them; bound and report them.

## Production SSRF boundary

Canonicalize once, enforce scheme/effective port and the exact authorized origin and
routes, reject redirects outside allowlisted routes, never follow the witness redirect.
Resolve DNS only after authorization, reject **all** answers if any are nonpublic,
private, loopback, link-local, reserved, multicast, unspecified, IPv4-mapped/private,
transitional or otherwise ambiguous. Pin a validated IP directly into the socket:
no second DNS lookup; check the actual peer address before sending HTTP. Preserve
original host in HTTP Host, TLS SNI and certificate validation. TLS verification is
mandatory, no inherited proxy, credentials, cookie jar or netrc. Redirect hops must
repeat route/origin policy, DNS and peer checks; no automatic HTTP-library redirect.
Disallow compression or bound decompression before parsing. Resource/body/time limits
and control-block halting apply to every outgoing request and hop.

**No production localhost escape hatch:** tests can inject an isolated transport in
unit contexts; an actual localhost demonstration fixture must be launched through a
separate laboratory-only harness unavailable through the normal API, with fixed
loopback destination and owned process, never a user-controllable private-IP bypass.
If that isolation cannot be demonstrated, production SSRF restrictions win and
laboratory live tests remain offline/mock-only, explicitly reported as such.

## Passive observations vs active controlled probes

Standard = authorized GET/HEAD of only submitted routes; observe TLS/certificate,
security headers, safe cookie attribute names (never values), redirects and script
origins declared by HTML without fetching scripts; public technical identifiers and
visible debug/directory indications. Capturing the response itself is a network
request, not passive listening, and may still generate ordinary server access logs.

Deep = standard + fixed controlled-origin CORS GET/OPTIONS, inert alphanumeric
reflection marker on specifically named approved query parameters, and an inert
witness destination for specifically designated redirect parameters. Never follow
the external witness. Each probe is one bounded request; no executable JavaScript,
SQLi/RCE/SSRF payload, authentication or target-side state change is intended.
Even GET/OPTIONS can have side effects on misdesigned systems; authorization and
scope must identify routes safe for such requests. Stop on security/WAF blocking;
no bypass, evasion or escalation. Reflection alone is not proof of XSS or execution.
CORS permissiveness alone is not proof of sensitive-data access. Redirection witness
can confirm a non-destructive open redirect behavior, not a broader compromise.
Second observation only if still within budget and does not cross a block.

Components: use only reliably explicit product/version declarations; compare to
already cached verified GHSA/CVE advisories when an exact ecosystem/package/version
mapping and range semantics can be justified. If matching cannot be implemented
safely for an ecosystem, report indeterminate—not a made-up vulnerability or fix.
Never query GHSA or any third party automatically from an audit.

## Finding, report and privacy contract

Each finding: check identifier, classification (conformant to performed checks /
attention / suspected / confirmed non-destructively / indeterminate), severity and
reason, minimal redacted observable proof, limitation, exploitation preconditions,
recommendation, official OWASP/advisory reference, date, authorized route and method.
No global score, certification, raw response persistence, cookie values, bearer
tokens, credentials, secrets or personal data in logs/report. Redact query values,
fragments, userinfo, cookies, authorization and server-controlled sensitive text;
store bounded structured derived facts only. Escape all target-controlled content
in HTML, strict CSP, no remote scripts/resources; local bilingual HTML printable and
readable in NIGHTFALL theme. Do not infer protection from a failure or unperformed test.

Report API should expose an authorized audit's structured results and HTML locally;
no sending, background scans, scheduler, auto-remediation or persistence outside the
isolated project. Database changes additive, no legacy data mutation, transactional
results and no implicit collection. Requests are manual through same local origin /
Host / X-Sentinel-Request guards and explicit confirmation; protect reports against
cross-site requests and injection. Never display or log full cookie or query values.

## References

- OWASP WSTG reflected XSS: https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting/
- OWASP WSTG CORS: https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing/
- OWASP SSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- OWASP Unvalidated Redirects Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html

These references inform the method; this scope does not implement all WSTG tests.
The stricter JLV limits above take precedence over any source examples.
