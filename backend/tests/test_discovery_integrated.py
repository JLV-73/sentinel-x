import json
import unittest
from unittest.mock import patch

from app import fortress_discovery_lab as lab


def test_actual_response_headers_are_attributed_per_page():
    routes = {
        '/': (200, b'<a href="/other">next</a>', None, [('Strict-Transport-Security', 'max-age=3600'), ('Set-Cookie', 'token=SECRET_COOKIE; Secure; HttpOnly')]),
        '/other': (200, b'SECRET_BODY', None, []),
    }
    with patch.object(lab, '_ROUTES', routes):
        result = lab.run_lab()
    pages = result['intelligence']['pages']
    assert [p['route'] for p in pages] == ['page-1', 'page-2']
    assert [p['graph_route'] for p in pages] == [lab._id('/'), lab._id('/other')]
    assert pages[0]['observations']['hsts'] != pages[1]['observations']['hsts']
    assert pages[1]['observations']['hsts'] == 'absent'
    assert result['graph']['relations'][0]['to'] == pages[1]['graph_route']
    assert 'SECRET_COOKIE' not in json.dumps(result)
    assert 'SECRET_BODY' not in json.dumps(result)
    routes['/'] = (200, routes['/'][1], None, [])
    with patch.object(lab, '_ROUTES', routes):
        changed = lab.run_lab()
    assert changed['intelligence']['pages'][0]['observations']['hsts'] == 'absent'


def test_redirect_and_forbidden_are_attributed_without_false_findings():
    routes = {
        '/': (302, b'SECRET_REDIRECT_BODY', '/denied', [('Set-Cookie', 'x=SECRET_COOKIE')]),
        '/denied': (403, b'SECRET_DENIED_BODY', None, [('Strict-Transport-Security', 'max-age=5')]),
    }
    original = lab.intelligence.analyze_pages
    with patch.object(lab, '_ROUTES', routes), patch.object(lab.intelligence, 'analyze_pages', wraps=original) as analyzer:
        result = lab.run_lab()
    assert analyzer.call_count == 1
    pages = result['intelligence']['pages']
    assert [(p['route'], p['status'], p['state']) for p in pages] == [
        ('page-1', 302, 'redirected'), ('page-2', 403, 'access_denied')]
    assert all(p['observations'] is None and p['findings'] == [] for p in pages)
    relation = result['graph']['relations'][0]
    assert (relation['from'], relation['to'], relation['kind']) == (pages[0]['graph_route'], pages[1]['graph_route'], 'redirect')
    assert result['reason'] == 'http_refused'
    assert 'SECRET_' not in json.dumps(result)


def load_tests(loader, tests, pattern):
    tests.addTest(unittest.FunctionTestCase(test_actual_response_headers_are_attributed_per_page))
    tests.addTest(unittest.FunctionTestCase(test_redirect_and_forbidden_are_attributed_without_false_findings))
    return tests
