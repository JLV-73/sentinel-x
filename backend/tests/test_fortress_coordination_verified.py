"""Independent, offline post-implementation security probes; no public traffic.

The socket adapter connects only to an owned loopback listener and simulates the
reported peer, so these are deadline tests, not proof of network pinning.
Cross-session and cross-user mutex ACLs are not exercised by these tests.
"""
import ctypes
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from app.fortress_service import _acquire_process_mutex, _release_process_mutex
from app.fortress_transport import SafeTransport, validate_scope
from test_fortress_tls_lab import certificates, TLSLab, client_context, transport_for, HOST

URL = 'http://deadline.invalid/'
PUBLIC = '93.184.216.34'  # simulated only; never connected


def session_id():
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    session = ctypes.c_ulong()
    assert kernel.ProcessIdToSessionId(os.getpid(), ctypes.byref(session))
    return session.value


@pytest.mark.skipif(os.name != 'nt', reason='Windows mutex only')
def test_global_mutex_same_session_process_contention_and_release():
    handle = _acquire_process_mutex()
    backend = str(Path(__file__).resolve().parents[1])
    script = '''import ctypes, os, sys
sys.path.insert(0, sys.argv[1])
from app.fortress_service import _acquire_process_mutex, _release_process_mutex, AuditError
sid=ctypes.c_ulong()
assert ctypes.WinDLL('kernel32').ProcessIdToSessionId(os.getpid(), ctypes.byref(sid))
try:
 h=_acquire_process_mutex()
except AuditError:
 print('denied', sid.value)
else:
 print('acquired', sid.value)
 _release_process_mutex(h)
'''
    def contender():
        result = subprocess.run([sys.executable, '-I', '-B', '-c', script, backend],
                                capture_output=True, text=True, timeout=10, check=True)
        parts = result.stdout.strip().split()
        assert len(parts) == 2
        return parts[0], int(parts[1])
    try:
        state, sid = contender()
        assert sid == session_id(), 'child session differs; result requires separate analysis'
        assert state == 'denied'
    finally:
        _release_process_mutex(handle)
    state, sid = contender()
    assert sid == session_id() and state == 'acquired'
    print('mutex: same-session independent process denied while held; acquired after release')


def test_blocking_dns_must_obey_hard_deadline():
    entered, release = threading.Event(), threading.Event()
    created = []
    def resolver(*args, **kwargs):
        entered.set()
        release.wait(2)
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, '', (PUBLIC, 80))]
    transport = SafeTransport(validate_scope(URL, []), resolver=resolver,
                              socket_factory=lambda *a: created.append(True), deadline=0.15, timeout=0.15)
    result = []
    t0 = time.monotonic()
    worker = threading.Thread(target=lambda: result.append(transport.observe_headers('GET', URL)))
    worker.start()
    try:
        assert entered.wait(1)
        worker.join(0.35)
        stuck = worker.is_alive()
        observed = time.monotonic() - t0
    finally:
        release.set()
        worker.join(3)
    assert not worker.is_alive()
    assert result == [{'outcome': 'error'}] and transport.blocked
    assert transport.observe_headers('GET', URL) == {'outcome': 'error'}
    assert transport.count == 1 and not created
    print(f'dns: deadline=0.150s still_running_at={observed:.3f}s: {stuck}; after_release=no socket or further attempt')
    assert not stuck, 'hard DNS deadline not enforced; synchronous resolver remained blocked'


def test_dns_slot_fails_closed_until_late_worker_finishes():
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    sockets, calls = [], []
    def resolver(*args, **kwargs):
        calls.append(True)
        entered.set()
        release.wait(3)
        finished.set()
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, '', (PUBLIC, 80))]
    def factory(*args):
        sockets.append(True)
        raise AssertionError('late DNS must never create a socket')
    first = SafeTransport(validate_scope(URL, []), resolver=resolver, socket_factory=factory, deadline=0.15)
    second = SafeTransport(validate_scope(URL, []), resolver=resolver, socket_factory=factory, deadline=0.15)
    try:
        assert first.observe('GET', URL) == {'outcome': 'error'}
        assert entered.is_set() and not finished.is_set()
        started = time.monotonic()
        assert second.observe('GET', URL) == {'outcome': 'error'}
        assert time.monotonic() - started < 0.10
        assert len(calls) == 1 and not sockets
    finally:
        release.set()
        assert finished.wait(2)
    time.sleep(0.05)
    assert not sockets and first.blocked and second.blocked


def test_real_tls_slow_headers_obey_deadline(certificates):
    class SlowTLSLab(TLSLab):
        def _serve(self):
            try:
                connection, _ = self.listener.accept()
                with connection, self.context.wrap_socket(connection, server_side=True) as tls:
                    self.record['handshake_complete'] = True
                    while b'\r\n\r\n' not in self.record['request']:
                        part = tls.recv(2048)
                        if not part:
                            return
                        self.record['request'] += part
                    for byte in b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n':
                        tls.sendall(bytes([byte]))
                        time.sleep(0.035)
            except OSError:
                pass
            finally:
                self.listener.close()
    lab = SlowTLSLab(certificates)
    try:
        transport, url = transport_for(lab, HOST, client_context(certificates / 'ca.pem'))
        transport.timeout = transport.deadline = 0.25
        started = time.monotonic()
        assert transport.observe_headers('GET', url) == {'outcome': 'error'}
        elapsed = time.monotonic() - started
        assert transport.observe_headers('GET', url) == {'outcome': 'error'}
    finally:
        lab.finish()
    assert lab.record.get('handshake_complete') and lab.record['sni'] == [HOST]
    assert lab.record['request'].count(b'GET ') == 1 and transport.count == 1
    assert elapsed < 0.45
    print(f'TLS header drip: deadline=0.250s elapsed={elapsed:.3f}s')


class LoopSocket:
    def __init__(self, address):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.address = address
    def connect(self, requested):
        assert requested == (PUBLIC, 80)
        self.sock.connect(self.address)
    def getpeername(self):
        assert self.sock.getpeername() == self.address
        return (PUBLIC, 80)  # test-only simulated peer
    def __getattr__(self, key):
        return getattr(self.sock, key)


class OwnedServer:
    def __init__(self, mode):
        self.mode = mode
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(('127.0.0.1', 0))
        self.sock.listen(2)
        self.sock.settimeout(2)
        self.address = self.sock.getsockname()
        self.requests = []
        self.errors = []
        self.thread = threading.Thread(target=self.run)
        self.thread.start()
    def run(self):
        try:
            conn, _ = self.sock.accept()
            with conn:
                conn.settimeout(2)
                data = b''
                while b'\r\n\r\n' not in data:
                    part = conn.recv(4096)
                    if not part:
                        break
                    data += part
                self.requests.append(data)
                if self.mode == 'header_drip':
                    for byte in b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n':
                        try:
                            conn.sendall(bytes([byte]))
                        except OSError:
                            break
                        time.sleep(0.035)
                elif self.mode == 'header_stall':
                    conn.sendall(b'HTTP/1.1 200 OK\r\nX-Test: ')
                    time.sleep(0.4)
                else:
                    conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n')
                    for _ in range(10):
                        try:
                            conn.sendall(b'x')
                        except OSError:
                            break
                        time.sleep(0.06)
                try:
                    extra = conn.recv(4096)
                    if extra:
                        self.requests.append(extra)
                except (OSError, TimeoutError):
                    pass
            self.sock.settimeout(0.3)
            try:
                conn, _ = self.sock.accept()
                with conn:
                    self.requests.append(conn.recv(4096))
            except socket.timeout:
                pass
        except Exception as exc:
            self.errors.append(type(exc).__name__)
        finally:
            self.sock.close()
    def finish(self):
        self.thread.join(4)
        assert not self.thread.is_alive()
        assert not self.errors, self.errors


@pytest.mark.parametrize('mode', ['header_stall', 'body_drip', 'header_drip'])
def test_loopback_deadline_and_no_further_request_after_timeout(mode):
    server = OwnedServer(mode)
    sockets = []
    def factory(*args):
        sock = LoopSocket(server.address)
        sockets.append(sock)
        return sock
    resolver_calls = []
    def resolver(*args, **kwargs):
        resolver_calls.append(True)
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, '', (PUBLIC, 80))]
    transport = SafeTransport(validate_scope(URL, []), resolver=resolver, socket_factory=factory,
                              timeout=0.15, deadline=0.15)
    try:
        start = time.monotonic()
        result = transport.observe_headers('GET', URL)
        elapsed = time.monotonic() - start
        second = transport.observe_headers('GET', URL)
    finally:
        server.finish()
    assert result == {'outcome': 'error'} and second == {'outcome': 'error'}
    assert transport.blocked and transport.count == len(resolver_calls) == len(sockets) == 1
    assert len(server.requests) == 1 and server.requests[0].count(b'GET ') == 1
    print(f'{mode}: deadline=0.150s elapsed={elapsed:.3f}s; subsequent request bytes=0')
    assert elapsed < 0.30, f'{mode}: hard deadline not enforced ({elapsed:.3f}s)'
