"""Test-only fixed owned-loopback harness; simulated peer is not provenance proof."""
import json
import socket
import threading
from app.fortress_transport import SafeTransport, validate_scope

HOST = 'fortress-lab.invalid'
SIMULATED_IP = '93.184.216.34'  # fabricated; never contacted
SENTINELS = ('lab-cookie-name-sentinel', 'lab-cookie-value-sentinel', 'lab-header-sentinel', 'lab-body-sentinel')

class OwnedHTTP:
    def __init__(self):
        self.requests, self.peers, self.errors = [], [], []
        self.stop = threading.Event()
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(4)
        self.listener.settimeout(.2)
        self.address = self.listener.getsockname()
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()
    def serve(self):
        try:
            while not self.stop.is_set():
                try:
                    conn, peer = self.listener.accept()
                except socket.timeout:
                    continue
                self.peers.append(peer)
                try:
                    with conn:
                        conn.settimeout(2)
                        data = b''
                        while b'\r\n\r\n' not in data and len(data) < 8192:
                            part = conn.recv(2048)
                            if not part:
                                break
                            data += part
                        self.requests.append(data)
                        path = data.split(b' ', 2)[1] if b' ' in data else b''
                        if path == b'/blocked':
                            payload = b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'
                        elif path == b'/redirect':
                            payload = b'HTTP/1.1 302 Found\r\nLocation: /outside\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'
                        else:
                            body = b'lab-body-sentinel'
                            payload = (b'HTTP/1.1 200 OK\r\nX-Lab: lab-header-sentinel\r\n'
                                b'Set-Cookie: lab-cookie-name-sentinel=lab-cookie-value-sentinel; Secure; HttpOnly; SameSite=Lax\r\n'
                                b'Set-Cookie: fictional=lab-cookie-value-sentinel\r\n'
                                b'Content-Length: ' + str(len(body)).encode() + b'\r\nConnection: close\r\n\r\n' + body)
                        conn.sendall(payload)
                except OSError as exc:
                    self.errors.append(type(exc).__name__)
        finally:
            self.listener.close()
    def close(self):
        self.stop.set()
        self.thread.join(3)
        assert not self.thread.is_alive() and self.listener.fileno() == -1

class SimulatedPublicPeerAdapter:
    def __init__(self, lab):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.lab = lab
        self.actual_peer = None
    def __getattr__(self, key):
        return getattr(self.sock, key)
    def connect(self, destination):
        assert destination == (SIMULATED_IP, 80)
        self.sock.connect(self.lab.address)
        self.actual_peer = self.sock.getpeername()
        assert self.actual_peer == self.lab.address and self.actual_peer[0] == '127.0.0.1'
    def getpeername(self):
        return (SIMULATED_IP, 80)  # deliberately simulated, not the actual peer

def make_transport(lab, paths=('/',), **kwargs):
    urls = [f'http://{HOST}{path}' for path in paths]
    resolutions, adapters = [], []
    def resolver(host, port, *, type):
        assert (host, port, type) == (HOST, 80, socket.SOCK_STREAM)
        resolutions.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, '', (SIMULATED_IP, 80))]
    def factory(family, kind, protocol):
        assert (family, kind, protocol) == (socket.AF_INET, socket.SOCK_STREAM, 0)
        adapter = SimulatedPublicPeerAdapter(lab)
        adapters.append(adapter)
        return adapter
    transport = SafeTransport(validate_scope(urls[0], urls[1:]), resolver=resolver,
                              socket_factory=factory, timeout=2, deadline=8, **kwargs)
    return transport, urls, resolutions, adapters

def run_owned_cookie_observation():
    lab = OwnedHTTP()
    try:
        transport, urls, resolutions, adapters = make_transport(lab)
        result = transport.observe('GET', urls[0])
        assert len(resolutions) == len(adapters) == len(lab.requests) == 1
        assert adapters[0].actual_peer == lab.address and lab.peers[0][0] == '127.0.0.1'
        assert lab.requests[0].startswith(f'GET / HTTP/1.1\r\nHost: {HOST}\r\n'.encode())
        assert b'Cookie:' not in lab.requests[0] and b'Authorization:' not in lab.requests[0]
        assert not lab.errors and all(s not in json.dumps(result) for s in SENTINELS)
        return result
    finally:
        lab.close()
