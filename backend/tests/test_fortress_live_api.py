import json
import threading
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
from fastapi import FastAPI
from app import fortress_mvp_api as api
from app.fortress_live import result

BASE = {'Origin': 'http://127.0.0.1:5177', 'X-Sentinel-Request': 'sync'}


class ApiTests(unittest.TestCase):
    def setUp(self):
        app = FastAPI()
        api.install_disabled_route(app, ('http://127.0.0.1:5177', 'http://127.0.0.1:8007'))
        self.client = TestClient(app, base_url='http://127.0.0.1:8007')
        token = self.client.get('/api/fortress/mvp/capability', headers=BASE).json()['capability']
        self.auth = {**BASE, 'X-Sentinel-Capability': token}

    def test_guard_and_strict_body(self):
        with patch.object(api, 'run_gated') as job:
            self.assertEqual(self.client.post('/api/fortress/audit', headers=BASE, json={'url': 'https://example.com/', 'consent': True}).status_code, 403)
            for body in ({'url': 'https://127.0.0.1/', 'consent': True}, {'url': 'https://example.com/', 'consent': 1}, {'url': 'https://example.com/', 'consent': True, 'x': 1}):
                self.assertEqual(self.client.post('/api/fortress/audit', headers=self.auth, json=body).status_code, 422)
            self.assertEqual(self.client.post('/api/fortress/audit', headers=self.auth, content=b'{"url":"https://example.com/","consent":true,"consent":true}').status_code, 415)
            self.assertEqual(self.client.post('/api/fortress/audit', headers={**self.auth, 'Content-Type': 'application/json'}, content=b'{"url":"https://example.com/","consent":true,"consent":true}').status_code, 422)
            job.assert_not_called()

    def test_supervisor_result_redacted_and_nostore(self):
        def fake(args, timeout, payload):
            self.assertNotIn('secret', str(args))
            self.assertEqual(json.loads(payload), 'https://example.com/p?secret=1')
            return json.dumps(result('https://example.com/')).encode()
        with patch.object(api, 'run_gated', side_effect=fake):
            response = self.client.post('/api/fortress/audit', headers=self.auth, json={'url': 'https://example.com/p?secret=1', 'consent': True})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertNotIn('secret', response.text)
        self.assertEqual(response.headers['cache-control'], 'no-store')

    def test_busy_while_worker_runs(self):
        entered, release = threading.Event(), threading.Event()
        def fake(*args):
            entered.set()
            release.wait(3)
            return json.dumps(result('https://example.com/')).encode()
        with patch.object(api, 'run_gated', side_effect=fake):
            first = threading.Thread(target=lambda: api._run_live('https://example.com/', 'https://example.com/'))
            first.start()
            self.assertTrue(entered.wait(2))
            try:
                with self.assertRaises(BlockingIOError):
                    api._run_live('https://example.com/', 'https://example.com/')
            finally:
                release.set()
                first.join(3)
