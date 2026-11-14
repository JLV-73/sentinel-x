import importlib.util
import unittest


class DiscoveryIntelligenceTests(unittest.TestCase):
    def test_complete_page_is_attributed_and_analyzed(self):
        self.assertIsNotNone(importlib.util.find_spec('app.fortress_discovery_intelligence'))
        from app.fortress_discovery_intelligence import analyze_pages
        result = analyze_pages([{'route': '/public', 'observed_at': '2026-01-01T12:00:00Z',
                                 'status': 200, 'complete': True, 'headers': []}])
        page = result['pages'][0]
        self.assertEqual(page['route'], 'page-1')
        self.assertEqual(page['method'], 'unknown')
        self.assertEqual(page['state'], 'complete')
        self.assertEqual(page['observations']['hsts'], 'absent')
        self.assertTrue(all(f['route'] == 'page-1' for f in page['findings']))
        self.assertEqual(page['provenance']['attestation'], 'none')

    def test_redirect_is_not_treated_as_final_page(self):
        from app.fortress_discovery_intelligence import analyze_pages
        result = analyze_pages([{'route': '/start', 'observed_at': '2026-01-01T12:00:00Z',
                                 'status': 302, 'complete': True, 'headers': []}])
        page = result['pages'][0]
        self.assertEqual(page['state'], 'redirected')
        self.assertIsNone(page['observations'])
        self.assertEqual(page['findings'], [])

    def test_server_error_does_not_yield_security_findings(self):
        from app.fortress_discovery_intelligence import analyze_pages
        result = analyze_pages([{'route': '/broken', 'observed_at': '2026-01-01T12:00:00Z',
                                 'status': 500, 'complete': True, 'headers': []}])
        self.assertEqual(result['pages'][0]['state'], 'http_error')
        self.assertIsNone(result['pages'][0]['observations'])
        self.assertEqual(result['pages'][0]['findings'], [])

    def test_multi_page_states_and_secret_free_projection(self):
        import json
        from app.fortress_discovery_intelligence import analyze_pages
        def page(route, status, complete, headers):
            return dict(route=route, observed_at='2026-01-01T12:00:00Z',
                        status=status, complete=complete, headers=headers)
        inputs = [page('/one', 200, True, [
            ('Set-Cookie', 'private_name=COOKIESECRET; Secure; HttpOnly'),
            ('Content-Security-Policy', "script-src 'unsafe-inline' 'nonce-NONCESECRET'"),
            ('Authorization', 'TOKENVALUE')]),
            page('/two', 200, True, [('Strict-Transport-Security', 'max-age=0')]),
            page('/refused', 403, True, []), page('/partial', None, False, [])]
        result = analyze_pages(inputs)
        a, b, denied, partial = result['pages']
        self.assertEqual([p['state'] for p in result['pages']], ['complete', 'complete', 'access_denied', 'incomplete'])
        self.assertEqual(b['observations']['hsts'], 'disabled')
        self.assertTrue(all(f['route'] == 'page-1' for f in a['findings']))
        self.assertTrue(all(f['route'] == 'page-2' for f in b['findings']))
        self.assertTrue(all(f.get('recommendation') and f.get('limit') and f.get('confidence') for p in (a,b) for f in p['findings']))
        self.assertIsNone(denied['observations'])
        self.assertEqual(denied['findings'], [])
        self.assertEqual(partial['findings'], [])
        rendered = json.dumps(result)
        for secret in ('private_name', 'COOKIESECRET', 'NONCESECRET', 'TOKENVALUE'):
            self.assertNotIn(secret, rendered)
        self.assertEqual(inputs[0]['headers'][0][1], 'private_name=COOKIESECRET; Secure; HttpOnly')

    def test_invalid_input_is_rejected(self):
        from app.fortress_discovery_intelligence import analyze_pages
        good = dict(route='/ok', observed_at='2026-01-01T12:00:00Z', status=200, complete=True, headers=[])
        for change in ({'route': '/ok?token=secret'}, {'route': '//evil'},
                       {'observed_at': '2026-01-01T12:00:00'}, {'status': True},
                       {'complete': 1}, {'headers': [('X', 'x\r\nInjected: secret')]}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                analyze_pages([{**good, **change}])
        with self.assertRaises(ValueError):
            analyze_pages([good, good])

    def test_incomplete_rejects_status_or_headers(self):
        from app.fortress_discovery_intelligence import analyze_pages
        page = dict(route='/partial', observed_at='2026-01-01T12:00:00Z', status=None, complete=False, headers=[])
        for change in ({'status': 200}, {'status': 403}, {'headers': [('X', 'v')]}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                analyze_pages([{**page, **change}])

    def test_paths_and_error_traceback_do_not_disclose_inputs(self):
        import json
        import traceback
        from app.fortress_discovery_intelligence import analyze_pages
        page = dict(route='/PATHSECRET', observed_at='2026-01-01T12:00:00Z', status=200, complete=True,
                    headers=[('Set-Cookie', 'COOKIENAME=COOKIEVALUE')])
        self.assertNotIn('PATHSECRET', json.dumps(analyze_pages([page])))
        page['headers'].append(('bad name', 'x'))
        try:
            analyze_pages([page])
        except ValueError as exc:
            self.assertIsNone(exc.__cause__)
            self.assertIsNone(exc.__context__)
            # Exclude caller frames: they own and may retain their original inputs.
            for frame in traceback.TracebackException.from_exception(exc, capture_locals=True).stack[1:]:
                for secret in ('PATHSECRET', 'COOKIENAME', 'COOKIEVALUE'):
                    self.assertNotIn(secret, str(frame.locals))
        else:
            self.fail('invalid headers accepted')

    def test_csp_policy_contexts_are_separate_and_bounded(self):
        from app.fortress_discovery_intelligence import analyze_pages
        page = dict(route='/a', observed_at='2026-01-01T12:00:00Z', status=200, complete=True,
                    headers=[('Content-Security-Policy', "default-src 'unsafe-inline'; script-src 'self'"),
                             ('Content-Security-Policy-Report-Only', "script-src 'unsafe-inline' 'nonce-PRIVATE'")])
        result = analyze_pages([page])['pages'][0]
        active = result['observations']['csp_effective']
        report = result['observations']['csp_report_only_effective']
        self.assertEqual({x['sink'] for x in active}, {'style-elem', 'style-attr'})
        self.assertEqual({x['mode'] for x in active}, {'review'})
        self.assertEqual({x['mode'] for x in report}, {'uncertain'})
        self.assertTrue(all(x['directive'] == 'script-src' for x in report))
        self.assertNotIn('PRIVATE', str(result))
        self.assertTrue(all('head_response' not in str(x) for x in result['findings']))

    def test_input_limits_and_core_exception_are_closed(self):
        from unittest.mock import patch
        import traceback
        from app.fortress_discovery_intelligence import analyze_pages
        page = dict(route='/sensitive', observed_at='2026-01-01T12:00:00Z', status=200, complete=True, headers=[])
        self.assertEqual(len(analyze_pages([{**page, 'route': f'/p{i}'} for i in range(100)])['pages']), 100)
        self.assertEqual(analyze_pages([{**page, 'headers': [('X', 'x' * 32767)]}])['pages'][0]['state'], 'complete')
        self.assertEqual(analyze_pages([{**page, 'headers': [('X', 'x')] * 256}])['pages'][0]['state'], 'complete')
        for bad in ([page] * 101, [{**page, 'headers': [('X', 'x')] * 257}],
                    [{**page, 'headers': [('X', 'x' * 32768)]}]):
            with self.assertRaises(ValueError):
                analyze_pages(bad)
        page['headers'] = [('Set-Cookie', 'SECRETNAME=SECRETVALUE')]
        with patch('app.fortress_discovery_intelligence.core.cookies', side_effect=RuntimeError('SECRETNAME=SECRETVALUE')):
            try:
                analyze_pages([page])
            except ValueError as exc:
                self.assertIsNone(exc.__cause__)
                self.assertIsNone(exc.__context__)
                frames = traceback.TracebackException.from_exception(exc, capture_locals=True).stack[1:]
                self.assertNotIn('SECRETNAME', str([f.locals for f in frames]))
                self.assertNotIn('SECRETVALUE', str([f.locals for f in frames]))
            else:
                self.fail('analysis error accepted')

    def test_changing_headers_changes_facts(self):
        from app.fortress_discovery_intelligence import analyze_pages
        page = dict(route='/x', observed_at='2026-01-01T12:00:00Z', status=200, complete=True, headers=[])
        before = analyze_pages([page])['pages'][0]['observations']['hsts']
        page['headers'] = [('Strict-Transport-Security', 'max-age=100')]
        after = analyze_pages([page])['pages'][0]['observations']['hsts']
        self.assertEqual((before, after), ('absent', 'positive'))


if __name__ == '__main__':
    unittest.main()
