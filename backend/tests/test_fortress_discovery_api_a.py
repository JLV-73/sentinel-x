def test_visible_api_references_are_only_counted():
    from app.fortress_discovery_a import summarize_html
    result = summarize_html('<a href="/api/items?token=SECRET_EXAMPLE">x</a><form action="/api/order"></form>', 'https://example.invalid/')
    assert result['api_references'] == 2
    assert 'SECRET_EXAMPLE' not in str(result)
