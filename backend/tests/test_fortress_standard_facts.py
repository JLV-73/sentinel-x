from test_fortress_transport import URL, build


def test_internal_standard_observer_exposes_only_bounded_header_enums():
    payload = (b'HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=12345; includeSubDomains\r\n'
               b"Content-Security-Policy: default-src 'none'\r\nX-Private: sentinel-secret\r\n"
               b'Content-Length: 0\r\n\r\n')
    result = build(payload)[0].observe_standard_facts('GET', URL)
    assert result == {'outcome': 'ok', 'header_value_facts': {'hsts': 'positive_max_age', 'csp': 'default_src_none'}}
    assert '12345' not in repr(result) and 'sentinel-secret' not in repr(result)
