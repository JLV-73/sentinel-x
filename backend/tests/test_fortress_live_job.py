import os
import sys
import time
import unittest

from app.fortress_job import run_gated


@unittest.skipUnless(os.name == 'nt', 'Windows job required')
class JobTests(unittest.TestCase):
    def test_gate_and_payload(self):
        code = "import sys; print(sys.stdin.buffer.readline().decode().strip(), sys.stdin.buffer.read().decode())"
        self.assertEqual(run_gated([sys.executable, '-c', code], 3, b'payload').strip(), b'GO payload')

    def test_real_gated_worker_blocks_private_dns_without_connect(self):
        import json
        from pathlib import Path
        backend = str(Path(__file__).resolve().parents[1])
        code = ("import sys,socket;sys.path.insert(0,sys.argv[1]);"
                "socket.getaddrinfo=lambda *a:[(socket.AF_INET,socket.SOCK_STREAM,6,'',('127.0.0.1',443))];"
                "from app.fortress_live_worker import main;raise SystemExit(main())")
        raw = run_gated([sys.executable, '-c', code, backend], 5, b'"https://example.com/private?secret=1"')
        observation = json.loads(raw)
        self.assertEqual(observation['failure_code'], 'blocked')
        self.assertEqual(observation['target'], 'https://example.com/')
        self.assertNotIn('secret', raw.decode())

    def test_timeout_kills_worker(self):
        code = "import sys,time; sys.stdin.buffer.readline(); time.sleep(10)"
        start = time.monotonic()
        with self.assertRaises(TimeoutError):
            run_gated([sys.executable, '-c', code], .3)
        self.assertLess(time.monotonic() - start, 3)
