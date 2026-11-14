"""Offline regression: excluded external navigation must not disappear."""
from app import fortress_discovery_policy as policy
from test_discovery_observed_exchange import invoke


def test_observed_external_link_is_counted_without_disclosing_it():
    body = b'<a href="https://outside.invalid/SECRET">outside</a>'
    response = invoke(b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: '
                      + str(len(body)).encode() + b'\r\n\r\n' + body)
    result = policy.discover_observed('https://example.invalid', ['/'], '/', lambda *args: response)
    assert not result['complete']
    assert 'excluded_links:1' in result['limits']
    assert 'outside.invalid' not in repr(result)
    assert 'SECRET' not in repr(result)
