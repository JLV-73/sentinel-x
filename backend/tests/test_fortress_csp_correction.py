import json
from app import fortress_mvp as m


def test_csp_duplicates_case_and_report_only_fail_closed_without_secrets():
    assert m._csp_details(["script-src 'none'; SCRIPT-SRC 'unsafe-inline'"]) == {'status': 'indeterminate', 'directives': []}
    assert m._csp_details(["script-src 'none'", "script-src 'unsafe-inline'"]) == {'status': 'indeterminate', 'directives': []}
    out = m._empty()
    raw = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Security-Policy-Report-Only: SCRIPT-SRC 'unsafe-inline' 'nonce-SECRET_CANARY' https://secret.invalid/path\r\nSet-Cookie: sid=COOKIE_CANARY; Secure\r\n\r\n"
    assert m._parse_response(raw, out)
    assert out['security_details']['csp']['status'] == 'missing'
    assert out['security_details']['csp_report_only']['directives'][0]['directive'] == 'script-src'
    assert all(s not in json.dumps(out) for s in ('SECRET_CANARY','secret.invalid','COOKIE_CANARY'))
