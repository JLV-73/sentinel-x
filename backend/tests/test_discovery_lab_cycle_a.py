import json
import unittest


class DiscoveryLabTests(unittest.TestCase):
    def test_real_owned_tls_fixture_crawls_multiple_pages_without_leaking_content(self):
        from app.fortress_discovery_lab import run_lab
        result = run_lab()
        self.assertEqual(result['pages'], 3)
        self.assertEqual(result['requests'], 4)
        self.assertTrue(result['complete'])
        self.assertNotIn('SECRET_EXAMPLE', json.dumps(result))
        self.assertNotIn('standard-lab.invalid', json.dumps(result))

    def test_requests_are_spaced(self):
        from unittest.mock import patch
        from app import fortress_discovery_lab as lab
        import time
        times = []
        original = lab._one_exchange
        def recording(path):
            times.append(time.monotonic())
            return original(path)
        with patch.object(lab, '_one_exchange', side_effect=recording):
            lab.run_lab(request_limit=2)
        self.assertGreaterEqual(times[1] - times[0], 0.7)

    def test_tls_rejects_untrusted_ca_and_wrong_hostname(self):
        import ssl
        from unittest.mock import patch
        from app import fortress_discovery_lab as lab
        untrusted = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        with patch.object(lab.ssl, 'create_default_context', return_value=untrusted):
            self.assertEqual(lab.run_lab()['reason'], 'incomplete')
        with patch.object(lab, '_NAME', 'wrong.invalid'):
            self.assertEqual(lab.run_lab()['reason'], 'incomplete')

    def test_no_dns_and_only_explicit_fixture_routes_are_requested(self):
        from unittest.mock import patch
        from app import fortress_discovery_lab as lab
        visited = []
        original = lab._one_exchange
        def recording(path):
            visited.append(path)
            return original(path)
        with patch.object(lab.socket, 'getaddrinfo', side_effect=AssertionError('DNS forbidden')), patch.object(lab, '_one_exchange', side_effect=recording):
            self.assertTrue(lab.run_lab()['complete'])
        self.assertEqual(visited, ['/', '/jump', '/second', '/third'])

    def test_exchange_refuses_unknown_route_before_socket_creation(self):
        from unittest.mock import patch
        from app import fortress_discovery_lab as lab
        with patch.object(lab.socket, 'socket', side_effect=AssertionError('socket opened')):
            with self.assertRaises(ValueError):
                lab._one_exchange('/delete')

    def test_existing_mvp_fixture_remains_operational(self):
        from app import fortress_mvp
        result = fortress_mvp.run_demo('ok')
        self.assertEqual(result['http_status'], 200)
        self.assertEqual(result['tls']['hostname'], 'verified')
        self.assertEqual(fortress_mvp.run_demo('tls-error')['failure_code'], 'tls_or_transport')

    def test_request_budget_includes_redirects(self):
        from app.fortress_discovery_lab import run_lab
        result = run_lab(request_limit=2)
        self.assertEqual(result['requests'], 2)
        self.assertFalse(result['complete'])
        self.assertEqual(result['reason'], 'request_limit')


if __name__ == '__main__':
    unittest.main()
