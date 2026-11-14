import importlib
import unittest


class PolicyTests(unittest.TestCase):
    def test_refuses_unlisted_route_before_transport(self):
        policy = importlib.import_module('app.fortress_discovery_policy')
        calls = []
        result = policy.discover('https://example.test', ['/'], '/not-allowed',
                                 lambda *args: calls.append(args))
        self.assertEqual(calls, [])
        self.assertFalse(result['complete'])
        self.assertEqual(result['reason'], 'scope_blocked')


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def response(status=200, size=0, links=(), location=None):
    return dict(status=status, decoded_bytes=size, links=links, location=location)


class MorePolicyTests(unittest.TestCase):
    def run_policy(self, pages, routes=('/',), start='/', limits=None, origin='https://example.test'):
        policy = importlib.import_module('app.fortress_discovery_policy')
        clock = Clock()
        calls = []
        def exchange(url, cap, timeout):
            calls.append((url, cap, timeout, clock.now))
            answer = pages[url]
            if isinstance(answer, Exception):
                raise answer
            return answer
        result = policy.discover(origin, routes, start, exchange, limits=limits, clock=clock, sleep=clock.sleep)
        return result, calls

    def test_normalization_and_same_origin(self):
        pages = {'https://example.test/': response(links=['https://EXAMPLE.test:443/next']),
                 'https://example.test/next': response()}
        result, calls = self.run_policy(pages, routes=['/', '/next'], origin='HTTPS://EXAMPLE.test:443/')
        self.assertTrue(result['complete'])
        self.assertEqual([c[0] for c in calls], list(pages))
        self.assertGreaterEqual(calls[1][3] - calls[0][3], .7)

    def test_empty_port_is_rejected_for_origin_start_link_and_redirect(self):
        result, calls = self.run_policy({}, origin='https://example.test:')
        self.assertEqual((result['reason'], calls), ('scope_blocked', []))
        result, calls = self.run_policy({}, start='https://example.test:/')
        self.assertEqual((result['reason'], calls), ('scope_blocked', []))
        for status, fields, reason in [(200, {'links': ['https://example.test:/next']}, 'scope_blocked'),
                                       (302, {'location': 'https://example.test:/next'}, 'redirect_blocked')]:
            with self.subTest(status=status):
                pages = {'https://example.test/': response(status, **fields)}
                result, calls = self.run_policy(pages, routes=['/', '/next'])
                self.assertEqual((result['reason'], len(calls), result['complete']), (reason, 1, False))

    def test_dangerous_explicit_allowlist_never_calls_transport(self):
        for path in ['/change-password', '/sign-out', '/account/close', '/api/items', '/delete']:
            with self.subTest(path=path):
                result, calls = self.run_policy({}, routes=[path], start=path)
                self.assertEqual(calls, [])
                self.assertEqual(result['reason'], 'scope_blocked')

    def test_ambiguous_urls_are_blocked_before_transport(self):
        for start in ['/?token=SECRET', '/#SECRET', '/a%2fb', '/a/../safe', '//evil.test/',
                      'https://user:pass@example.test/', 'https://example.test.evil/', '/a\\b', '/a//b']:
            with self.subTest(start=start):
                result, calls = self.run_policy({}, routes=['/', '/safe'], start=start)
                self.assertEqual(calls, [])
                self.assertFalse(result['complete'])

    def test_redirects_rechecked_and_secret_never_returned(self):
        for location in ['https://outside.test/', '/change-password', '/next?token=SECRET', '/unknown']:
            with self.subTest(location=location):
                pages = {'https://example.test/': response(302, location=location)}
                result, calls = self.run_policy(pages, routes=['/', '/next'])
                self.assertEqual(len(calls), 1)
                self.assertEqual(result['reason'], 'redirect_blocked')
                self.assertNotIn('SECRET', repr(result))

    def test_redirects_share_budget_and_cycle_detection(self):
        policy = importlib.import_module('app.fortress_discovery_policy')
        pages = {'https://example.test/': response(302, size=2, location='/next'),
                 'https://example.test/next': response(302, size=3, location='/')}
        result, calls = self.run_policy(pages, routes=['/', '/next'])
        self.assertEqual(result['reason'], 'redirect_loop')
        self.assertEqual((result['requests'], result['bytes']), (2, 5))
        self.assertEqual(len(calls), 2)
        result, calls = self.run_policy(pages, routes=['/', '/next'], limits=policy.Limits(requests=1))
        self.assertEqual((result['reason'], len(calls)), ('request_limit', 1))

    def test_204_continues_pending_routes_and_respects_request_budget(self):
        policy = importlib.import_module('app.fortress_discovery_policy')
        pages = {'https://example.test/': response(links=['/a', '/b']),
                 'https://example.test/a': response(204),
                 'https://example.test/b': response()}
        result, calls = self.run_policy(pages, routes=['/', '/a', '/b'])
        self.assertEqual((result['complete'], result['reason'], result['pages'], result['requests']),
                         (True, 'none', 3, 3))
        self.assertEqual([call[0] for call in calls], list(pages))
        result, calls = self.run_policy(pages, routes=['/', '/a', '/b'],
                                        limits=policy.Limits(requests=2))
        self.assertEqual((result['complete'], result['reason'], result['pages'], len(calls)),
                         (False, 'request_limit', 2, 2))

    def test_depth_and_pages_limits_are_partial(self):
        policy = importlib.import_module('app.fortress_discovery_policy')
        pages = {'https://example.test/': response(links=['/a']),
                 'https://example.test/a': response(links=['/b']),
                 'https://example.test/b': response()}
        for limits, reason, count in [(policy.Limits(depth=1), 'depth_limit', 2),
                                      (policy.Limits(pages=1), 'page_limit', 1)]:
            result, calls = self.run_policy(pages, routes=['/', '/a', '/b'], limits=limits)
            self.assertEqual((result['reason'], len(calls), result['complete']), (reason, count, False))

    def test_depth_limited_link_already_pending_is_complete_when_visited(self):
        policy = importlib.import_module('app.fortress_discovery_policy')
        pages = {'https://example.test/': response(links=['/a', '/b']),
                 'https://example.test/a': response(links=['/b']),
                 'https://example.test/b': response()}
        result, calls = self.run_policy(pages, routes=['/', '/a', '/b'],
                                        limits=policy.Limits(depth=1))
        self.assertEqual([call[0] for call in calls], list(pages))
        self.assertEqual((result['complete'], result['reason']), (True, 'none'))

    def test_depth_limited_link_later_reached_by_redirect_is_complete(self):
        policy = importlib.import_module('app.fortress_discovery_policy')
        pages = {'https://example.test/': response(links=['/a', '/c']),
                 'https://example.test/a': response(links=['/b']),
                 'https://example.test/c': response(302, location='/b'),
                 'https://example.test/b': response()}
        result, calls = self.run_policy(pages, routes=['/', '/a', '/b', '/c'],
                                        limits=policy.Limits(depth=1))
        self.assertEqual([call[0] for call in calls], list(pages))
        self.assertEqual((result['complete'], result['reason']), (True, 'none'))

    def test_resolved_depth_limit_does_not_hide_blocked_scope(self):
        policy = importlib.import_module('app.fortress_discovery_policy')
        pages = {'https://example.test/': response(links=['/a', '/b']),
                 'https://example.test/a': response(links=['/b', '/unlisted']),
                 'https://example.test/b': response()}
        result, calls = self.run_policy(pages, routes=['/', '/a', '/b'],
                                        limits=policy.Limits(depth=1))
        self.assertEqual(len(calls), 3)
        self.assertEqual((result['complete'], result['reason']), (False, 'scope_blocked'))

    def test_pending_depth_route_does_not_override_request_limit(self):
        policy = importlib.import_module('app.fortress_discovery_policy')
        pages = {'https://example.test/': response(links=['/a', '/b']),
                 'https://example.test/a': response(links=['/b'])}
        result, calls = self.run_policy(pages, routes=['/', '/a', '/b'],
                                        limits=policy.Limits(depth=1, requests=2))
        self.assertEqual(len(calls), 2)
        self.assertEqual((result['complete'], result['reason']), (False, 'request_limit'))

    def test_byte_caps_pass_remaining_before_request(self):
        policy = importlib.import_module('app.fortress_discovery_policy')
        pages = {'https://example.test/': response(size=4, links=['/a']),
                 'https://example.test/a': response(size=2)}
        limits = policy.Limits(page_bytes=5, total_bytes=6)
        result, calls = self.run_policy(pages, routes=['/', '/a'], limits=limits)
        self.assertTrue(result['complete'])
        self.assertEqual([c[1] for c in calls], [5, 2])
        pages['https://example.test/a'] = response(size=3)
        result, calls = self.run_policy(pages, routes=['/', '/a'], limits=limits)
        self.assertEqual(result['reason'], 'byte_limit')
        self.assertLessEqual(result['bytes'], 6)

    def test_duration_budget_prevents_next_request(self):
        policy = importlib.import_module('app.fortress_discovery_policy')
        pages = {'https://example.test/': response(links=['/a']), 'https://example.test/a': response()}
        result, calls = self.run_policy(pages, routes=['/', '/a'], limits=policy.Limits(seconds=.7))
        self.assertEqual((result['reason'], len(calls)), ('duration_limit', 1))

    def test_invalid_options_rejected(self):
        policy = importlib.import_module('app.fortress_discovery_policy')
        for options in [dict(pages=21), dict(requests=31), dict(depth=3), dict(interval=.69),
                        dict(page_bytes=512*1024+1), dict(total_bytes=10*1024*1024+1),
                        dict(seconds=121), dict(seconds=float('nan')), dict(pages=True)]:
            with self.subTest(options=options), self.assertRaises(ValueError):
                policy.Limits(**options)

    def test_visited_redirect_is_not_a_cycle(self):
        pages = {'https://example.test/': response(links=['/a', '/b']),
                 'https://example.test/a': response(),
                 'https://example.test/b': response(302, location='/a')}
        result, calls = self.run_policy(pages, routes=['/', '/a', '/b'])
        self.assertTrue(result['complete'])
        self.assertEqual(result['requests'], 3)
        self.assertEqual(len(calls), 3)

    def test_late_transport_result_is_not_accepted(self):
        policy = importlib.import_module('app.fortress_discovery_policy')
        clock = Clock()
        def exchange(url, cap, timeout):
            clock.now += timeout
            return response(size=5)
        result = policy.discover('https://example.test', ['/'], '/', exchange,
                                 limits=policy.Limits(seconds=1), clock=clock, sleep=clock.sleep)
        self.assertEqual(result['reason'], 'duration_limit')
        self.assertEqual(result['pages'], 0)
        self.assertFalse(result['complete'])

    def test_no_socket_or_dns_even_in_successful_simulation(self):
        from unittest.mock import patch
        with patch('socket.socket', side_effect=AssertionError('network')), \
             patch('socket.getaddrinfo', side_effect=AssertionError('dns')):
            result, calls = self.run_policy({'https://example.test/': response()})
        self.assertTrue(result['complete'])
        self.assertEqual(len(calls), 1)

    def test_errors_and_links_do_not_leak_secrets(self):
        result, _ = self.run_policy({'https://example.test/': RuntimeError('SECRET')})
        self.assertEqual(result['reason'], 'transport_error')
        self.assertNotIn('SECRET', repr(result))
        result, calls = self.run_policy({'https://example.test/': response(links=['/x?token=SECRET'])})
        self.assertFalse(result['complete'])
        self.assertEqual(len(calls), 1)
        self.assertNotIn('SECRET', repr(result))


if __name__ == '__main__':
    unittest.main()
