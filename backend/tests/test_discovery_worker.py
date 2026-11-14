import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from app import fortress_discovery_worker as worker


@unittest.skipUnless(os.name == 'nt', 'Windows job laboratory')
class DiscoveryWorkerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ['TMPDIR'])
        self.addCleanup(self.tmp.cleanup)
        self.marker = str(Path(self.tmp.name) / 'proof')

    def wait_started(self):
        end = time.monotonic() + 5
        while not Path(self.marker + '.started').exists():
            if time.monotonic() >= end:
                self.fail('synthetic DNS was not reached')
            time.sleep(.02)

    def test_success_and_positive_late_effect_control(self):
        result = worker.run_lab('descendant', timeout=5, delay=.6, marker=self.marker)
        self.assertEqual(result, {'error': 'blocked', 'status': None, 'decoded_bytes': None})
        self.assertTrue(Path(self.marker + '.started').exists())
        self.assertTrue(Path(self.marker + '.late').exists())
        self.assertTrue(Path(self.marker + '.descendant.started').exists())
        self.assertTrue(Path(self.marker + '.descendant').exists())

    def test_blocked_dns_and_descendant_have_no_late_effect_after_timeout(self):
        errors = []
        def run():
            try:
                worker.run_lab('descendant', timeout=1.5, delay=4, marker=self.marker)
            except Exception as exc:
                errors.append(exc)
        thread = threading.Thread(target=run)
        thread.start()
        self.wait_started()
        thread.join(8)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], TimeoutError)
        self.assertTrue(Path(self.marker + '.descendant.started').exists())
        time.sleep(4.3)
        self.assertFalse(Path(self.marker + '.late').exists())
        self.assertFalse(Path(self.marker + '.descendant').exists())

    def test_exclusion_between_independent_parent_processes(self):
        errors = []
        def run():
            try:
                worker.run_lab('dns_gate', timeout=10, marker=self.marker)
            except Exception as exc:
                errors.append(exc)
        thread = threading.Thread(target=run)
        thread.start()
        try:
            self.wait_started()
            backend = str(Path(worker.__file__).resolve().parents[1])
            other_marker = self.marker + '.other'
            code = ("import sys;sys.path.insert(0,sys.argv[1]);"
                    "from app.fortress_discovery_worker import run_lab;"
                    "run_lab('dns_delay',timeout=5,delay=0,marker=sys.argv[2])")
            other = subprocess.run([sys.executable, '-I', '-c', code, backend, other_marker],
                                   capture_output=True, timeout=7)
            self.assertTrue(thread.is_alive(), 'first worker must still hold exclusion')
            self.assertNotEqual(other.returncode, 0)
            self.assertIn(b'child failed', other.stderr)
            self.assertFalse(Path(other_marker + '.started').exists())
        finally:
            Path(self.marker + '.release').write_text('release', encoding='ascii')
            thread.join(12)
        self.assertFalse(thread.is_alive())
        self.assertFalse(errors)
        result = worker.run_lab('dns_delay', timeout=5, marker=other_marker)
        self.assertEqual(result, {'error': 'blocked', 'status': None, 'decoded_bytes': None})
        self.assertTrue(Path(other_marker + '.started').exists())

    def test_invalid_parameters_refused(self):
        for timeout in (0, float('nan'), float('inf'), True):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                worker.run_lab('dns_delay', timeout=timeout)
        with self.assertRaises(ValueError):
            worker.run_lab('network', timeout=1)
