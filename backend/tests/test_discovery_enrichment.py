from app import fortress_discovery_policy as policy
from app import fortress_discovery_transport as transport
from app.fortress_discovery_contract import valid_lab


def test_exclusions_count_references_without_leaking_values():
    parser = transport._Links('https://example.invalid/', report_excluded=True)
    parser.feed('<a href="https://outside.invalid/x">a</a><a href="https://outside.invalid/x">b</a>'
                '<a href="/q?token=SECRET">c</a><a href="/login">d</a>'
                '<a href="/file.js">e</a><a href="/not-allowed">f</a>')
    obs = transport._evidence(200, 1, [], full=True)['evidence']
    def exchange(*args):
        return {'status': 200, 'decoded_bytes': 1, 'links': parser.links,
                'location': None, 'observations': obs}
    result = policy.discover_observed('https://example.invalid', ['/'], '/', exchange)
    # Transport's legacy None deliberately discards reason, so do not guess.
    assert result['exclusion_reasons'] == {'external': 0, 'query_fragment': 0, 'sensitive': 1,
        'non_html_resource': 1, 'invalid': 0, 'out_of_scope': 1, 'depth': 0, 'unknown': 3}
    assert valid_lab(result)
    assert 'SECRET' not in repr(result)
