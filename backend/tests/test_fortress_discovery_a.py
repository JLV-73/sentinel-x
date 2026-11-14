import json


def test_discovery_projection_counts_references_without_exposing_contents():
    from app.fortress_discovery_a import summarize_html

    html = '''<a href="/about">About</a><a href="/logout">out</a>
    <a href="https://outside.invalid/">external</a><a href="/find?token=SECRET_EXAMPLE">find</a>
    <script src="/app.js"></script><link rel="stylesheet" href="/app.css">
    <form action="/api/secret-SECRET_EXAMPLE" method="post"></form>'''
    result = summarize_html(html, 'https://example.invalid/')
    assert result == {'internal_links': 1, 'excluded_links': 3, 'scripts': 1,
                      'stylesheets': 1, 'forms': 1, 'api_references': 1}
    assert 'SECRET_EXAMPLE' not in json.dumps(result)
