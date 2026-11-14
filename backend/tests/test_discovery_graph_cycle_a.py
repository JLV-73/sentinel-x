import json
import unittest
from unittest.mock import patch

from app import fortress_discovery_lab as lab


class GraphTests(unittest.TestCase):
    def test_fixture_links_drive_graph_metamorphically(self):
        routes = {'/': (200, b'<a href="/novel">go</a>'), '/novel': (200, b'<p>SECRET_EXAMPLE</p>')}
        with patch.object(lab, '_ROUTES', routes):
            result = lab.run_lab()
        self.assertEqual(len(result['graph']['pages']), 2)
        self.assertEqual(len(result['graph']['relations']), 1)
        self.assertEqual(result['graph']['relations'][0]['kind'], 'link')
        self.assertNotIn('SECRET_EXAMPLE', json.dumps(result))
        with patch.object(lab, '_ROUTES', {'/': (200, b'<a href="/different">go</a>'), '/different': (200, b'')}):
            other = lab.run_lab()
        self.assertNotEqual(result['graph'], other['graph'])

    def test_rejections_normalization_and_resources(self):
        html = (b'<a href="/a/../ok#part">1</a><a href="/ok#two">2</a>'
                b'<a href="/delete">x</a><a href="/ok?secret=TOKEN">x</a>'
                b'<a href="https://outside.invalid/">x</a><a href="/%64elete">x</a>'
                b'<script src="/secret.js"></script><link rel="stylesheet" href="/style.css">'
                b'<form action="/api/secret"></form><a href="/api/data">api</a>')
        visits = []
        original = lab._one_exchange
        def record(path):
            visits.append(path)
            return original(path)
        with patch.object(lab, '_ROUTES', {'/': (200, html), '/ok': (200, b'')}), patch.object(lab, '_one_exchange', side_effect=record):
            result = lab.run_lab()
        self.assertEqual(visits, ['/', '/ok'])
        self.assertEqual(len(result['graph']['relations']), 1)
        self.assertEqual({r['kind'] for r in result['graph']['resources']}, {'script', 'stylesheet', 'form', 'api'})
        self.assertNotIn('TOKEN', json.dumps(result))

    def test_outside_redirect_is_blocked_without_following(self):
        routes = {'/': (302, b'', 'https://outside.invalid/')}
        with patch.object(lab, '_ROUTES', routes):
            result = lab.run_lab()
        self.assertEqual(result['reason'], 'redirect_blocked')
        self.assertEqual(result['requests'], 1)

    def test_redirect_to_previously_visited_page_is_not_a_loop(self):
        routes = {'/': (200, b'<a href="/page">page</a><a href="/jump">jump</a>'),
                  '/page': (200, b''), '/jump': (302, b'', '/page')}
        visits = []
        original = lab._one_exchange
        def record(path):
            visits.append(path)
            return original(path)
        with patch.object(lab, '_ROUTES', routes), patch.object(lab, '_one_exchange', side_effect=record):
            result = lab.run_lab()
        self.assertEqual(visits, ['/', '/page', '/jump'])
        self.assertTrue(result['complete'])
        self.assertEqual((result['reason'], result['requests'], result['pages']), ('none', 3, 2))
        self.assertIn({'from': lab._id('/jump'), 'to': lab._id('/page'), 'kind': 'redirect'},
                      result['graph']['relations'])

    def test_redirect_chain_cycle_is_reported_without_repeated_request(self):
        routes = {'/': (302, b'', '/a'), '/a': (302, b'', '/b'), '/b': (302, b'', '/a')}
        visits = []
        original = lab._one_exchange
        def record(path):
            visits.append(path)
            return original(path)
        with patch.object(lab, '_ROUTES', routes), patch.object(lab, '_one_exchange', side_effect=record):
            result = lab.run_lab()
        self.assertEqual(visits, ['/', '/a', '/b'])
        self.assertFalse(result['complete'])
        self.assertEqual((result['reason'], result['requests']), ('redirect_loop', 3))
        self.assertIn({'from': lab._id('/b'), 'to': lab._id('/a'), 'kind': 'redirect'},
                      result['graph']['relations'])

    def test_depth_limit_records_pending_target(self):
        routes = {'/': (200, b'<a href="/one">1</a>'), '/one': (200, b'<a href="/two">2</a>'),
                  '/two': (200, b'<a href="/three">3</a>')}
        with patch.object(lab, '_ROUTES', routes):
            result = lab.run_lab()
        self.assertEqual(result['reason'], 'depth_limit')
        self.assertEqual(result['requests'], 3)
        self.assertEqual(len(result['graph']['relations']), 3)
        self.assertFalse(result['complete'])

    def test_page_budget_caps_real_fixture(self):
        routes = {'/': (200, b''.join(('<a href="/p%d">x</a>' % i).encode() for i in range(25)))}
        routes.update({'/p%d' % i: (200, b'') for i in range(25)})
        with patch.object(lab, '_ROUTES', routes):
            result = lab.run_lab()
        self.assertEqual((result['pages'], result['requests'], result['reason']), (20, 20, 'page_limit'))

    def test_redirects_consume_30_request_budget(self):
        routes = {'/': (302, b'', '/r0')}
        routes.update({'/r%d' % i: (302, b'', '/r%d' % (i + 1)) for i in range(31)})
        with patch.object(lab, '_ROUTES', routes):
            result = lab.run_lab()
        self.assertEqual((result['requests'], result['reason']), (30, 'request_limit'))
        self.assertEqual(len(result['graph']['relations']), 30)
