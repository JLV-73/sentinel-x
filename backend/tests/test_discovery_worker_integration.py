import unittest
import traceback
import json
from unittest.mock import patch
from app import fortress_discovery_worker as worker


class DiscoveryIntegrationTests(unittest.TestCase):
    def test_malformed_worker_output_is_rejected_without_raw_exception_state(self):
        from app.fortress_discovery_policy import Limits
        marker = 'SECRET_SYNTHETIC_OUTPUT_82'
        with patch.object(worker, 'run_gated', return_value=('{"' + marker).encode()):
            try:
                worker.run_discovery_lab('https://example.invalid', ['/'], '/', limits=Limits(), timeout=5)
            except RuntimeError as exc:
                self.assertIsNone(exc.__context__)
                self.assertIsNone(exc.__cause__)
                captured = traceback.TracebackException.from_exception(exc, capture_locals=True)
                rendered = ''.join(traceback.format_list([frame for frame in captured.stack
                                                          if frame.filename == worker.__file__]))
                self.assertNotIn(marker, rendered)
            else:
                self.fail('malformed output accepted')

    def test_duplicate_keys_and_contradictory_results_rejected(self):
        from app.fortress_discovery_policy import Limits
        outputs = [
            b'{"pages":0,"pages":1,"requests":1,"bytes":0,"complete":true,"reason":"none"}',
            b'{"pages":2,"requests":1,"bytes":0,"complete":true,"reason":"none"}',
            b'{"pages":0,"requests":1,"bytes":99999999,"complete":false,"reason":"incomplete"}',
            b'{"pages":0,"requests":0,"bytes":0,"complete":true,"reason":"incomplete"}',
            b'{"pages":0,"requests":1,"bytes":0,"complete":false,"reason":"none"}',
            b'{"pages":0,"requests":1,"bytes":0,"complete":false,"reason":"page_limit"}',
            b'{"pages":0,"requests":1,"bytes":0,"complete":false,"reason":"request_limit"}',
            b'{"pages":0,"requests":2,"bytes":0,"complete":false,"reason":"incomplete"}',
            b'{"pages":0,"requests":1,"bytes":524289,"complete":false,"reason":"incomplete"}',
            b'{"pages":false,"requests":1,"bytes":0,"complete":false,"reason":"incomplete"}',
            b'{"pages":1,"requests":1,"bytes":0,"complete":false,"reason":"transport_error"}',
            b'{"pages":0,"requests":1,"bytes":0,"complete":false,"reason":"depth_limit"}',
        ]
        for raw in outputs:
            with self.subTest(raw=raw), patch.object(worker, 'run_gated', return_value=raw):
                with self.assertRaisesRegex(RuntimeError, 'invalid lab result'):
                    worker.run_discovery_lab('https://example.invalid', ['/'], '/', limits=Limits(), timeout=5)

    def test_invalid_structured_output_and_synthetic_mode_hide_raw(self):
        from app.fortress_discovery_policy import Limits
        marker = 'SECRET_OTHER_SYNTHETIC_91'
        for discovery in (True, False):
            raw = ('{"pages":0,"requests":1,"bytes":0,"complete":false,"reason":"' + marker + '"}').encode()
            with self.subTest(discovery=discovery), patch.object(worker, 'run_gated', return_value=raw):
                try:
                    if discovery:
                        worker.run_discovery_lab('https://example.invalid', ['/'], '/', limits=Limits(), timeout=5)
                    else:
                        worker.run_lab('dns_delay', timeout=5)
                except RuntimeError as exc:
                    self.assertIsNone(exc.__context__)
                    self.assertIsNone(exc.__cause__)
                    captured = traceback.TracebackException.from_exception(exc, capture_locals=True)
                    rendered = ''.join(traceback.format_list([frame for frame in captured.stack
                                                              if frame.filename == worker.__file__]))
                    self.assertNotIn(marker, rendered)
                else:
                    self.fail('invalid output accepted')

    def test_policy_valid_complete_and_partial_results_are_preserved(self):
        from app.fortress_discovery_policy import Limits
        for result in (
            {'pages': 1, 'requests': 1, 'bytes': 0, 'complete': True, 'reason': 'none'},
            {'pages': 0, 'requests': 1, 'bytes': 0, 'complete': False, 'reason': 'incomplete'},
            {'pages': 0, 'requests': 0, 'bytes': 0, 'complete': False, 'reason': 'duration_limit'},
            {'pages': 1, 'requests': 1, 'bytes': 2, 'complete': False, 'reason': 'page_limit'},
        ):
            with self.subTest(result=result), patch.object(worker, 'run_gated', return_value=json.dumps(result).encode()):
                self.assertEqual(worker.run_discovery_lab('https://example.invalid', ['/', '/other'], '/',
                                                         limits=Limits(pages=1), timeout=5), result)

    def test_private_worker_accepts_scoped_budget_and_remains_offline(self):
        from app.fortress_discovery_policy import Limits
        result = worker.run_discovery_lab('https://example.invalid', ['/'], '/',
                                          limits=Limits(seconds=4), timeout=5)
        self.assertEqual(result, {'pages': 0, 'requests': 1, 'bytes': 0,
                                  'complete': False, 'reason': 'incomplete'})

    def test_invalid_scope_is_rejected(self):
        from app.fortress_discovery_policy import Limits
        for origin, routes, start in [
            ('https://example.com', ['/'], '/'),
            ('https://example.invalid', ['/delete'], '/delete'),
            ('https://example.invalid', ['/'], '/not-allowed'),
        ]:
            with self.subTest(start=start), self.assertRaises(RuntimeError):
                worker.run_discovery_lab(origin, routes, start, limits=Limits(seconds=4), timeout=5)
