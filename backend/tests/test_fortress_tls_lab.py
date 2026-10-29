"""Offline TLS lab: peer reported to transport is simulated, not provenance proof."""
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading

import pytest

from app.fortress_transport import SafeTransport, TransportError, validate_scope

HOST = 'fortress-lab.invalid'
URL = f'https://{HOST}/'
APPROVED = ('93.184.216.34', 443)  # fabricated DNS answer; never contacted
SCRATCH = Path(os.environ['LOCALAPPDATA']) / 'hermes' / 'cache' / 'scratch'


@pytest.fixture(scope='module')
def certificates():
    SCRATCH.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='fortress-tls-', dir=SCRATCH) as name:
        root = Path(name)
        config = root / 'openssl.cnf'
        config.write_text('[req]\ndistinguished_name = dn\n[dn]\n', encoding='ascii')
        extensions = root / 'extensions.cnf'
        extensions.write_text('subjectAltName=DNS:' + HOST + '\nextendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE\n', encoding='ascii')
        env = dict(os.environ, OPENSSL_CONF=str(config))
        def run(*args):
            subprocess.run(['openssl', *args], cwd=root, env=env, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30)
        run('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '1', '-subj', '/CN=Fortress Test CA', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
        run('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'server.key', '-out', 'server.csr', '-subj', '/CN=' + HOST)
        run('x509', '-req', '-in', 'server.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'server.pem', '-days', '1', '-extfile', str(extensions))
        yield root


class LocalSocketAdapter:
    """Test-only: actual connect fixed to owned listener; peer report is simulated."""
    def __init__(self, listener_address, record):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener_address = listener_address
        self.record = record

    def __getattr__(self, key):
        return getattr(self.sock, key)

    def connect(self, destination):
        assert destination == APPROVED
        self.record['requested_destination'] = destination
        self.sock.connect(self.listener_address)
        self.record['actual_connected_peer'] = self.sock.getpeername()
        assert self.record['actual_connected_peer'] == self.listener_address

    def getpeername(self):
        self.record['simulated_reported_peer'] = APPROVED
        return APPROVED


class TLSLab:
    def __init__(self, certificates):
        self.record = {'sni': [], 'request': b'', 'server_errors': []}
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(str(certificates / 'server.pem'), str(certificates / 'server.key'))
        self.context.set_servername_callback(lambda sock, name, context: self.record['sni'].append(name))
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(1)
        self.listener.settimeout(5)
        self.address = self.listener.getsockname()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        try:
            connection, client_address = self.listener.accept()
            self.record['actual_client_address'] = client_address
            connection.settimeout(5)
            with connection:
                with self.context.wrap_socket(connection, server_side=True) as tls:
                    self.record['handshake_complete'] = True
                    data = b''
                    while b'\r\n\r\n' not in data and len(data) < 8192:
                        part = tls.recv(2048)
                        if not part:
                            break
                        data += part
                    self.record['request'] = data
                    tls.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK')
        except (OSError, ssl.SSLError) as exc:
            self.record['server_errors'].append(type(exc).__name__)
        finally:
            self.listener.close()

    def finish(self):
        self.thread.join(7)
        if self.thread.is_alive():
            self.listener.close()
            self.thread.join(2)
        assert not self.thread.is_alive(), 'laboratory listener did not terminate'


def resolver(host, port, *, type):
    assert host in (HOST, 'wrong-fortress-lab.invalid') and port == 443 and type == socket.SOCK_STREAM
    return [(socket.AF_INET, socket.SOCK_STREAM, 0, '', APPROVED)]


def transport_for(lab, hostname, context):
    url = f'https://{hostname}/'
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
    wrap = context.wrap_socket
    def observed_wrap(*args, **kwargs):
        try:
            return wrap(*args, **kwargs)
        except ssl.SSLCertVerificationError as exc:
            lab.record['verify_code'] = exc.verify_code
            raise
    context.wrap_socket = observed_wrap
    def factory(family, kind, protocol):
        assert (family, kind, protocol) == (socket.AF_INET, socket.SOCK_STREAM, 0)
        return LocalSocketAdapter(lab.address, lab.record)
    return SafeTransport(validate_scope(url, []), resolver=resolver, socket_factory=factory,
                         tls_context=context, timeout=4), url


def client_context(ca=None):
    # No default roots: CA acceptance is solely the supplied ephemeral test root.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if ca is not None:
        context.load_verify_locations(cafile=str(ca))
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
    return context


def test_real_tls_valid_sni_host_and_observer(certificates):
    lab = TLSLab(certificates)
    try:
        transport, url = transport_for(lab, HOST, client_context(certificates / 'ca.pem'))
        result = transport.observe('GET', url)
    finally:
        lab.finish()
    assert result == {'outcome': 'ok', 'cookies': {'count': 0, 'missing_secure': 0, 'missing_httponly': 0, 'missing_samesite': 0, 'indeterminate': 0}}
    assert lab.record['sni'] == [HOST]
    assert lab.record.get('handshake_complete') is True
    assert lab.record['request'] == (f'GET / HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n').encode('ascii')
    assert lab.record['actual_connected_peer'] == lab.address
    assert lab.address[0] == '127.0.0.1'
    assert lab.record['actual_client_address'][0] == '127.0.0.1'
    assert lab.record['requested_destination'] == lab.record['simulated_reported_peer'] == APPROVED
    assert not lab.record['server_errors']


@pytest.mark.parametrize('hostname,trust', [('wrong-fortress-lab.invalid', True), (HOST, False)])
def test_real_tls_rejects_hostname_mismatch_or_untrusted_ca(certificates, hostname, trust):
    lab = TLSLab(certificates)
    try:
        context = client_context(certificates / 'ca.pem' if trust else None)
        transport, url = transport_for(lab, hostname, context)
        assert transport.observe('GET', url) == {'outcome': 'error'}
        assert transport.blocked
    finally:
        lab.finish()
    assert lab.record['sni'] == [hostname]
    assert lab.record['verify_code'] == (62 if trust else 20)  # hostname mismatch / missing issuer
    assert lab.record['request'] == b''
    assert not lab.record.get('handshake_complete', False)
    assert lab.record['actual_connected_peer'] == lab.address
    assert lab.record['simulated_reported_peer'] == APPROVED
    assert lab.record['server_errors']


def test_fake_peer_mismatch_refused_before_tls_or_http():
    class FakePeer:
        def settimeout(self, timeout): pass
        def connect(self, destination): assert destination == APPROVED
        def getpeername(self): return ('127.0.0.1', 443)
        def close(self): pass
    transport = SafeTransport(validate_scope(URL, []), resolver=resolver,
                              socket_factory=lambda *args: FakePeer())
    with pytest.raises(TransportError):
        transport.request('GET', URL)
    assert transport.blocked
