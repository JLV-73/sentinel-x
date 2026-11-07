from app import fortress_mvp as m


def response(headers):
    out = m._empty()
    data = b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n' + headers + b'\r\n'
    assert m._parse_response(data, out)
    return out


def test_hsts_and_csp_details():
    out = response(b"Strict-Transport-Security: max-age=0\r\nContent-Security-Policy: script-src 'unsafe-inline' *\r\n")
    assert out['security_details']['hsts'] == {'status': 'disabled', 'seconds': 0}
    assert out['security_details']['csp']['status'] == 'present'
    assert out['security_details']['csp']['directives'] == [{'directive': 'script-src', 'inline': True, 'wildcard': 'any'}]


def test_hsts_ambiguous_and_report_only():
    out = response(b"Strict-Transport-Security: max-age=1; max-age=0\r\nContent-Security-Policy-Report-Only: script-src 'unsafe-inline'\r\n")
    assert out['security_details']['hsts']['status'] == 'indeterminate'
    assert out['security_details']['csp']['status'] == 'missing'
    assert out['security_details']['csp_report_only']['directives'][0]['inline'] is True
