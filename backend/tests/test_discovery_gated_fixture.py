import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import sys
import threading
import time
import unittest
from dataclasses import asdict

# Test-only executable: never selected by application code.
if __name__ == '__main__' and len(sys.argv) > 1 and sys.argv[1] == 'fixture-child':
    sys.path.insert(0, sys.argv[2])
    from app import fortress_discovery_worker as worker, fortress_discovery_transport as transport
    mode, port, marker = sys.argv[3], int(sys.argv[4]), sys.argv[5]
    def guard():
        if mode == 'dns':
            def blocked(*args):
                Path(marker + '.started').write_text('1')
                time.sleep(4)
                Path(marker + '.late').write_text('1')
                return []
            transport.socket.getaddrinfo = blocked
            transport.socket.socket = lambda *a, **k: (_ for _ in ()).throw(RuntimeError())
        else:
            real_socket = socket.socket
            class LocalSocket(real_socket):
                def connect(self, address):
                    if address != ('127.0.0.1', port):
                        raise ValueError('fixture only')
                    return super().connect(address)
            transport._resolve = lambda host, requested: (socket.AF_INET, '127.0.0.1') if host == 'standard-lab.invalid' and requested == port else (_ for _ in ()).throw(ValueError())
            transport.public_ip = ipaddress.ip_address
            transport.socket.socket = LocalSocket
            ca = Path(transport.__file__).with_name('fortress_mvp_tls') / 'ca.pem'
            ssl.SSLContext.load_default_certs = lambda ctx: ctx.load_verify_locations(cafile=str(ca))
    worker._guard_network = guard
    if mode == 'live_tls':
        original = worker._discovery_observed_live
        def fixture_only(data):
            guard()
            return original(data)
        worker._discovery_observed_live = fixture_only
    raise SystemExit(worker._child())

from app import fortress_discovery_worker as worker
from app.fortress_discovery_policy import Limits
from app.fortress_job import run_gated


@unittest.skipUnless(os.name == 'nt', 'Windows job laboratory')
class GatedFixtureTests(unittest.TestCase):
    def invoke_fixture(self, mode, port, marker, timeout=6):
        origin = 'https://standard-lab.invalid:' + str(port)
        payload = json.dumps({'mode': 'discovery', 'origin': origin, 'routes': ['/', '/next'], 'start': '/',
                              'limits': asdict(Limits(seconds=5))}).encode('ascii')
        backend = str(Path(worker.__file__).resolve().parents[1])
        args = [sys.executable, '-I', '-B', str(Path(__file__).resolve()), 'fixture-child', backend, mode, str(port), marker]
        return json.loads(run_gated(args, timeout, payload))

    def test_gated_real_tls_fixture_uses_policy_and_transport(self):
        certs = Path(worker.__file__).with_name('fortress_mvp_tls')
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(certs / 'server.pem'), str(certs / 'server-key.pem'))
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(('127.0.0.1', 0))
        listener.listen(2)
        listener.settimeout(8)
        port = listener.getsockname()[1]
        requests, errors = [], []
        handlers = []
        def handle(conn, body):
            try:
                with conn:
                    conn.settimeout(5)
                    with context.wrap_socket(conn, server_side=True) as tls:
                        req = b''
                        while b'\r\n\r\n' not in req:
                            chunk = tls.recv(4096)
                            if not chunk:
                                raise RuntimeError('truncated request')
                            req += chunk
                        requests.append(req.split(b' ')[1])
                        response = b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body
                        tls.sendall(response)
                        try:
                            tls.unwrap().close()
                        except (ssl.SSLEOFError, ConnectionResetError, ConnectionAbortedError):
                            pass
            except Exception as exc:
                errors.append(type(exc).__name__)
        def serve():
            try:
                for body in (b'<a href="/next">SECRET_BODY</a>', b'finished'):
                    conn = listener.accept()[0]
                    handler = threading.Thread(target=handle, args=(conn, body))
                    handlers.append(handler)
                    handler.start()
            except Exception as exc:
                errors.append(type(exc).__name__)
        thread = threading.Thread(target=serve)
        thread.start()
        try:
            result = self.invoke_fixture('tls', port, '')
        finally:
            thread.join(9)
            for handler in handlers:
                handler.join(6)
            listener.close()
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [], (result, requests))
        self.assertEqual(requests, [b'/', b'/next'])
        self.assertEqual(result['pages'], 2)
        self.assertEqual(result['requests'], 2)
        self.assertTrue(result['complete'])
        self.assertNotIn('SECRET_BODY', repr(result))
        self.assertNotIn('/next', repr(result))

    def test_live_mode_real_job_and_private_tls_fixture(self):
        from unittest.mock import patch
        certs = Path(worker.__file__).with_name('fortress_mvp_tls')
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(certs / 'server.pem'), str(certs / 'server-key.pem'))
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(10)
        port = listener.getsockname()[1]
        requests, errors = [], []
        def serve():
            try:
                conn, _ = listener.accept()
                with conn, context.wrap_socket(conn, server_side=True) as tls:
                    tls.settimeout(5)
                    req = b''
                    while b'\r\n\r\n' not in req:
                        chunk = tls.recv(4096)
                        if not chunk:
                            raise RuntimeError('truncated')
                        req += chunk
                    requests.append(req)
                    tls.sendall(b'HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=0\r\nContent-Length: 0\r\n\r\n')
                    try:
                        tls.unwrap().close()
                    except (ssl.SSLEOFError, ConnectionResetError, ConnectionAbortedError):
                        pass
            except Exception as exc:
                errors.append(type(exc).__name__)
        thread = threading.Thread(target=serve)
        thread.start()
        backend = str(Path(worker.__file__).resolve().parents[1])
        def fixture_gate(argv, timeout, payload):
            args = [sys.executable, '-I', '-B', str(Path(__file__).resolve()), 'fixture-child', backend, 'live_tls', str(port), '']
            return run_gated(args, min(timeout, 10), payload)
        try:
            with patch.object(worker, 'run_gated', fixture_gate):
                result = worker.run_observed_live(f'https://standard-lab.invalid:{port}/', ['/'])
        finally:
            thread.join(12)
            listener.close()
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(len(requests), 1)
        self.assertTrue(requests[0].startswith(b'GET / HTTP/1.1\r\n'))
        self.assertEqual(result['provenance'], 'live')  # Synthetic harness, not an Internet observation.
        self.assertEqual(result['pages'][0]['observations']['hsts'], 'disabled')

    def test_gated_discovery_stops_blocked_dns_and_excludes_other_process(self):
        import tempfile
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as tmp:
            marker = str(Path(tmp) / 'dns')
            errors = []
            def invoke():
                try:
                    self.invoke_fixture('dns', 443, marker, timeout=1.8)
                except Exception as exc:
                    errors.append(exc)
            thread = threading.Thread(target=invoke)
            thread.start()
            end = time.monotonic() + 5
            while not Path(marker + '.started').exists() and time.monotonic() < end:
                time.sleep(.02)
            self.assertTrue(Path(marker + '.started').exists())
            with self.assertRaises(RuntimeError):
                self.invoke_fixture('dns', 443, marker + 'other', timeout=2)
            thread.join(8)
            self.assertFalse(thread.is_alive())
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], TimeoutError)
            time.sleep(4.2)
            self.assertFalse(Path(marker + '.late').exists())
            self.assertFalse(Path(marker + 'other.started').exists())
