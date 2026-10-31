"""Experimental owned-loopback standard lab. Not connected to production API.

The public peer and DNS are simulated; this cannot validate real TLS or SSRF.
"""
import json
import http.server
import secrets
import signal
import time
from pathlib import Path
import socket
import sys
import threading

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))
sys.path.insert(0, str(ROOT / 'backend' / 'tests'))
from app.fortress_service import _audit_with_factory
from app.fortress_transport import SafeTransport
from support_fortress_api import _project

HOST = 'standard-lab.invalid'
FAKE_IP = '93.184.216.34'  # identity simulated; never contacted
SCENARIOS = frozenset(('positive', 'negative', 'indeterminate'))


class FixtureSocket:
    def __init__(self, listener):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener = listener
        self.address = listener.getsockname()
        self.connected = False

    def __getattr__(self, name):
        return getattr(self.sock, name)

    def connect(self, destination):
        if (destination != (FAKE_IP, 80) or self.listener.fileno() < 0
                or self.listener.getsockname() != self.address or self.address[0] != '127.0.0.1'):
            raise RuntimeError('fixture only')
        self.sock.connect(self.address)
        if self.sock.getpeername() != self.address:
            raise RuntimeError('fixture peer mismatch')
        self.connected = True

    def getpeername(self):
        if not self.connected:
            raise RuntimeError('not connected')
        return (FAKE_IP, 80)


def run_scenario(scenario):
    if type(scenario) is not str or scenario not in SCENARIOS:
        raise ValueError('unknown scenario')
    payload = {'level': 'standard', 'authorized': True, 'routes': [{'url': 'http://' + HOST + '/',
        'safe_use_confirmed': True, 'methods': ['GET'], 'cors_get': False, 'parameters': []}]}
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(3)
        requests = []
        def fixture():
            try:
                conn, peer = listener.accept()
                with conn:
                    conn.settimeout(2)
                    data = b''
                    while b'\r\n\r\n' not in data and len(data) < 8192:
                        part = conn.recv(2048)
                        if not part:
                            return
                        data += part
                    if (peer[0] != '127.0.0.1' or not data.startswith(b'GET / HTTP/1.1\r\nHost: standard-lab.invalid\r\n')
                            or b'\r\nCookie:' in data or b'\r\nAuthorization:' in data):
                        return
                    requests.append(1)
                    if scenario == 'indeterminate':
                        response = b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'
                    else:
                        cookie = b'Set-Cookie: lab-cookie=lab-secret; HttpOnly; SameSite=Lax' + (b'; Secure' if scenario == 'positive' else b'') + b'\r\n'
                        response = b'HTTP/1.1 200 OK\r\n' + cookie + b'Content-Length: 0\r\nConnection: close\r\n\r\n'
                    conn.sendall(response)
            except OSError:
                return
        worker = threading.Thread(target=fixture, daemon=True)
        worker.start()
        def resolver(host, port, *, type):
            if (host, port, type) != (HOST, 80, socket.SOCK_STREAM):
                raise RuntimeError('unexpected DNS')
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, '', (FAKE_IP, 80))]
        def socket_factory(family, kind, protocol):
            if (family, kind, protocol) != (socket.AF_INET, socket.SOCK_STREAM, 0):
                raise RuntimeError('unexpected socket')
            return FixtureSocket(listener)
        def factory(scope, **kwargs):
            return SafeTransport(scope, resolver=resolver, socket_factory=socket_factory, timeout=2, deadline=3, **kwargs)
        try:
            result = _audit_with_factory(payload, factory=factory)
            worker.join(3)
            if worker.is_alive() or requests != [1]:
                raise RuntimeError('fixture failed')
            return _project(result, payload)
        finally:
            listener.close()
            worker.join(3)


class Handler(http.server.BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(2)

    def log_message(self, *args):
        pass

    def send_error(self, code, message=None, explain=None):
        # The stdlib includes the untrusted method/request text in errors.
        self.send(code, b'{}')

    def send(self, status, body, content_type='application/json', nonce=None):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Cross-Origin-Resource-Policy', 'same-origin')
        self.send_header('Connection', 'close')
        if nonce:
            self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'nonce-" + nonce + "'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def common(self):
        host = '127.0.0.1:' + str(self.server.server_port)
        return (self.client_address[0] == '127.0.0.1' and self.headers.get_all('Host') == [host]
                and not self.headers.get_all('Transfer-Encoding', []) and not self.headers.get_all('Content-Encoding', []))

    def do_GET(self):
        origin = 'http://127.0.0.1:' + str(self.server.server_port)
        if (not self.common() or self.path != '/lab/' or self.headers.get_all('Content-Length', []) not in ([], ['0'])
                or self.headers.get_all('Origin', []) not in ([], [origin])
                or self.headers.get_all('Sec-Fetch-Site', []) not in ([], ['none'], ['same-origin'])
                or self.headers.get_all('Sec-Fetch-Mode', []) not in ([], ['navigate'])
                or self.headers.get_all('Sec-Fetch-Dest', []) not in ([], ['document'])):
            self.send(403, b'{}'); return
        nonce = secrets.token_urlsafe(24)
        page = (ROOT / 'scripts' / 'fortress_standard_lab_page.html').read_text(encoding='utf-8')
        page = page.replace('__CAPABILITY__', self.server.capability).replace('__NONCE__', nonce)
        self.send(200, page.encode('utf-8'), 'text/html; charset=utf-8', nonce)

    def do_POST(self):
        origin = 'http://127.0.0.1:' + str(self.server.server_port)
        capability = self.headers.get_all('X-Fortress-Capability', [])
        lengths = self.headers.get_all('Content-Length', [])
        if (not self.common() or self.path != '/lab/audit' or self.headers.get_all('Origin') != [origin]
                or self.headers.get_all('X-Fortress-CSRF') != ['same-origin']
                or self.headers.get_all('Content-Type') != ['application/json']
                or len(capability) != 1 or not capability[0].isascii()
                or not secrets.compare_digest(capability[0], self.server.capability)):
            self.send(403, b'{}'); return
        if len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit() or not 0 < int(lengths[0]) <= 256:
            self.send(400, b'{}'); return
        def pairs(items):
            d = {}
            for k, v in items:
                if k in d: raise ValueError()
                d[k] = v
            return d
        try:
            data = json.loads(self.rfile.read(int(lengths[0])), object_pairs_hook=pairs)
            if type(data) is not dict or set(data) != {'scenario'} or type(data['scenario']) is not str or data['scenario'] not in SCENARIOS:
                raise ValueError()
        except (ValueError, UnicodeError, OSError, RecursionError):
            self.send(400, b'{}'); return
        try:
            result = run_scenario(data['scenario'])
            self.send(200, json.dumps(result, separators=(',', ':')).encode('ascii'))
        except Exception:
            self.send(503, b'{}')


class LabServer(http.server.HTTPServer):
    def handle_error(self, request, client_address):
        # Request processing may fail after the watchdog closes a slow client.
        # Never emit a traceback, peer address, or request/capability data.
        pass

    def __init__(self, *args):
        self.active = None
        self.active_since = 0
        self.lock = threading.Lock()
        super().__init__(*args)

    def get_request(self):
        conn, address = super().get_request()
        with self.lock:
            self.active, self.active_since = conn, time.monotonic()
        return conn, address

    def shutdown_request(self, request):
        with self.lock:
            if self.active is request:
                self.active = None
        super().shutdown_request(request)

    def interrupt_active(self, expired_only=False):
        with self.lock:
            if self.active is None or (expired_only and time.monotonic() - self.active_since < 2):
                return
            try:
                self.active.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def serve_bounded(server, stopped, ttl):
    server.timeout = .1
    deadline = time.monotonic() + ttl
    def requests():
        while not stopped.is_set():
            try:
                server.handle_request()
            except OSError:
                break
    worker = threading.Thread(target=requests, daemon=True, name='standard-lab-http')
    worker.start()
    try:
        while not stopped.wait(.02) and time.monotonic() < deadline:
            server.interrupt_active(expired_only=True)
    finally:
        stopped.set()
        server.interrupt_active()
        server.server_close()
        worker.join(timeout=.5)


def serve():
    if len(sys.argv) != 1:
        raise SystemExit('No arguments accepted')
    stopped = threading.Event()
    old = {}
    for sig in (signal.SIGINT, getattr(signal, 'SIGBREAK', signal.SIGINT)):
        if sig not in old:
            old[sig] = signal.signal(sig, lambda *_: stopped.set())
    try:
        with LabServer(('127.0.0.1', 0), Handler) as server:
            server.capability = secrets.token_urlsafe(32)
            print('http://127.0.0.1:%d/lab/' % server.server_port, flush=True)
            serve_bounded(server, stopped, 60)
    finally:
        for sig, handler in old.items(): signal.signal(sig, handler)


if __name__ == '__main__':
    serve()
