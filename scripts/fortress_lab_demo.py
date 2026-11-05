"""Isolated synthetic loopback lab; not a production adapter or audit endpoint.

The parent process owns the fixture listener. The adapter deliberately reports
an invented public peer to exercise SafeTransport; it proves neither real DNS nor
production peer validation. No real site or user data is contacted or inspected.
"""
import http.server
import json
from pathlib import Path
import socket
import sys
import time
import threading
import secrets
import signal

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))
from app.fortress_transport import SafeTransport, validate_scope

HOST = 'fortress-lab.invalid'
FAKE_IP = '93.184.216.34'  # simulated only, never connected
URL = 'http://fortress-lab.invalid/'


def _fixture(listener, stop, evidence, deadline):
    try:
        conn = None
        while not stop.is_set() and time.monotonic() < deadline:
            listener.settimeout(min(.2, max(.001, deadline - time.monotonic())))
            try:
                conn, peer = listener.accept()
                break
            except socket.timeout:
                continue
        if conn is None:
            return
        with conn:
            request = b''
            while b'\r\n\r\n' not in request and len(request) < 8192:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or stop.is_set():
                    return
                conn.settimeout(min(.2, remaining))
                try:
                    part = conn.recv(2048)
                except socket.timeout:
                    continue
                if not part:
                    return
                request += part
            if (not request.startswith(b'GET / HTTP/1.1\r\nHost: fortress-lab.invalid\r\n')
                    or b'Cookie:' in request or b'Authorization:' in request or peer[0] != '127.0.0.1'):
                return
            body = b'lab-body-sentinel'
            conn.settimeout(max(.001, deadline - time.monotonic()))
            conn.sendall(b'HTTP/1.1 200 OK\r\nSet-Cookie: lab-cookie-name-sentinel=lab-cookie-value-sentinel; Secure; HttpOnly; SameSite=Lax\r\nSet-Cookie: fictional=lab-cookie-value-sentinel\r\nContent-Length: ' + str(len(body)).encode() + b'\r\nConnection: close\r\n\r\n' + body)
            evidence.append({'requests': 1, 'actual_peer_loopback': True})
    except (OSError, ValueError):
        return


class _LabSocket:
    def __init__(self, listener):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener = listener
        self._address = listener.getsockname()
        self.connected = False

    def __getattr__(self, name):
        return getattr(self._socket, name)

    def connect(self, destination):
        if (destination != (FAKE_IP, 80) or self._listener.fileno() < 0
                or self._listener.getsockname() != self._address or self._address[0] != '127.0.0.1'):
            raise RuntimeError('fixture destination rejected')
        self._socket.connect(self._address)
        if self._socket.getpeername() != self._address:
            raise RuntimeError('fixture peer mismatch')
        self.connected = True

    def getpeername(self):
        if not self.connected:
            raise RuntimeError('not connected')
        return (FAKE_IP, 80)  # simulated only


def run_demo():
    stop, evidence = threading.Event(), []
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        deadline = time.monotonic() + 5
        worker = threading.Thread(target=_fixture, args=(listener, stop, evidence, deadline), daemon=True, name='fortress-lab-fixture')
        worker.start()
        try:
            def resolver(host, port, *, type):
                if (host, port, type) != (HOST, 80, socket.SOCK_STREAM):
                    raise RuntimeError('unexpected resolution')
                return [(socket.AF_INET, socket.SOCK_STREAM, 0, '', (FAKE_IP, 80))]
            def factory(family, kind, protocol):
                if (family, kind, protocol) != (socket.AF_INET, socket.SOCK_STREAM, 0):
                    raise RuntimeError('unexpected socket')
                return _LabSocket(listener)
            scope = validate_scope(URL, [])
            transport = SafeTransport(scope, resolver=resolver, socket_factory=factory,
                                      timeout=2, deadline=4, max_requests=1,
                                      allowed_methods=frozenset({(next(iter(scope.routes)), 'GET')}))
            observation = transport.observe('GET', URL)
            worker.join(timeout=max(0, deadline - time.monotonic()))
            if worker.is_alive() or observation.get('outcome') != 'ok' or evidence != [{'requests': 1, 'actual_peer_loopback': True}]:
                raise RuntimeError('fixture observation failed')
            return {'mode': 'synthetic-owned-loopback', 'observation': observation, 'fixture': evidence[0],
                    'limits': 'Simulated DNS and peer; not a production audit or proof of production network protections.'}
        finally:
            stop.set()
            worker.join(timeout=1)
            if worker.is_alive():
                listener.close()
                worker.join(timeout=1)


class _Handler(http.server.BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(2)

    def log_message(self, *args):
        pass

    def _base_ok(self):
        host = '127.0.0.1:' + str(self.server.server_port)
        return (self.client_address[0] == '127.0.0.1' and self.headers.get_all('Host') == [host]
                and self.headers.get_all('Transfer-Encoding', []) == []
                and self.headers.get_all('Content-Length', []) in ([], ['0'])
                and self.headers.get_all('Content-Type', []) == [])

    def do_GET(self):
        host = '127.0.0.1:' + str(self.server.server_port)
        if (not self._base_ok() or self.path != '/lab/'
                or self.headers.get_all('Origin', []) not in ([], ['http://' + host])
                or self.headers.get_all('Sec-Fetch-Site', []) not in ([], ['none'], ['same-origin'])
                or self.headers.get_all('Sec-Fetch-Mode', []) not in ([], ['navigate'])
                or self.headers.get_all('Sec-Fetch-Dest', []) not in ([], ['document'])):
            self.send_error(403)
            return
        try:
            nonce = secrets.token_urlsafe(24)
            body = (ROOT / 'scripts' / 'fortress_lab_page.html').read_text(encoding='utf-8').replace('__NONCE__', nonce).replace('__CAPABILITY__', self.server.capability).encode('utf-8')
        except OSError:
            self.send_error(503)
            return
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'nonce-" + nonce + "'; style-src 'unsafe-inline'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
        self.send_header('Cross-Origin-Resource-Policy', 'same-origin')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        host = '127.0.0.1:' + str(self.server.server_port)
        token = self.headers.get_all('X-Fortress-Capability', [])
        if (not self._base_ok() or self.path != '/lab/observation'
                or self.headers.get_all('Content-Length', []) != ['0']
                or self.headers.get_all('Origin', []) != ['http://' + host]
                or self.headers.get_all('Sec-Fetch-Site', []) != ['same-origin']
                or self.headers.get_all('Sec-Fetch-Mode', []) != ['cors']
                or self.headers.get_all('Sec-Fetch-Dest', []) != ['empty']
                or len(token) != 1 or not token[0].isascii()
                or not secrets.compare_digest(token[0], self.server.capability)):
            self.send_error(403)
            return
        try:
            body = json.dumps(run_demo(), separators=(',', ':')).encode('utf-8')
        except Exception:
            self.send_error(503)
            return
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Cross-Origin-Resource-Policy', 'same-origin')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _LabServer(http.server.HTTPServer):
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
            conn = self.active
            if conn is None or (expired_only and time.monotonic() - self.active_since < 2):
                return
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def serve():
    stopped = threading.Event()
    old_handlers = {}
    def stop_signal(signum, frame):
        stopped.set()
    for sig in (signal.SIGINT, getattr(signal, 'SIGBREAK', signal.SIGINT)):
        if sig not in old_handlers:
            old_handlers[sig] = signal.signal(sig, stop_signal)
    try:
        with _LabServer(('127.0.0.1', 0), _Handler) as server:
            server.capability = secrets.token_urlsafe(32)
            server.timeout = .1
            deadline = time.monotonic() + 60
            def requests():
                while not stopped.is_set():
                    try:
                        server.handle_request()
                    except OSError:
                        break
            worker = threading.Thread(target=requests, daemon=True, name='fortress-lab-http')
            worker.start()
            try:
                print('http://127.0.0.1:%d/lab/' % server.server_port, flush=True)
                while not stopped.wait(.05) and time.monotonic() < deadline:
                    server.interrupt_active(expired_only=True)
            finally:
                stopped.set()
                server.interrupt_active()
                server.server_close()
                worker.join(timeout=.5)
    finally:
        for sig, handler in old_handlers.items():
            signal.signal(sig, handler)


def main():
    if not sys.argv[1:]:
        serve()
    else:
        raise SystemExit('No arguments accepted')


if __name__ == '__main__':
    main()
