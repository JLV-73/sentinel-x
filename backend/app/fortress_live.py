"""Bounded HTTPS HEAD engine. Never invoke with an untrusted connected socket."""
import datetime
import ipaddress
import re
import socket
import ssl
import time
from urllib.parse import urlsplit

from .fortress_mvp import _public_ip

_NAMES = {'hsts': b'strict-transport-security', 'csp': b'content-security-policy',
          'x_content_type_options': b'x-content-type-options', 'referrer_policy': b'referrer-policy',
          'permissions_policy': b'permissions-policy'}
_LIMIT = 32768
_HOST = re.compile(r'(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')
_FIELD = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+:[\x09\x20-\x7e\x80-\xff]*")
_TOKEN = rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
_CODING = re.compile(_TOKEN)
_PARAMETER = re.compile(rb'[ \t]*;[ \t]*' + _TOKEN + rb'[ \t]*=[ \t]*(?:' + _TOKEN
                        + rb'|"(?:[\x09\x20\x21\x23-\x5b\x5d-\x7e\x80-\xff]|\\[\x09\x20-\x7e\x80-\xff])*")')


def _valid_transfer_encoding(value):
    # Parse delimiters outside quoted parameter values; chunked must be unique and final.
    pos = 0
    chunked = False
    while True:
        match = _CODING.match(value, pos)
        if not match or chunked:
            return False
        chunked = match.group().lower() == b'chunked'
        pos = match.end()
        while parameter := _PARAMETER.match(value, pos):
            if chunked:
                return False
            pos = parameter.end()
        while pos < len(value) and value[pos] in b' \t':
            pos += 1
        if pos == len(value):
            return True
        if value[pos] != ord(','):
            return False
        pos += 1
        while pos < len(value) and value[pos] in b' \t':
            pos += 1


def public_ip(value):
    ip = _public_ip(value)
    if ip.version == 4 and ip in ipaddress.ip_network('192.88.99.0/24'):
        raise ValueError('IPv4 relay address')
    # Exclude transition mechanisms embedding an IPv4 destination (including
    # NAT64/6to4/Teredo), regardless of Python version's is_global table.
    if ip.version == 6 and (ip not in ipaddress.ip_network('2000::/3')
                            or ip in ipaddress.ip_network('2002::/16')
                            or ip in ipaddress.ip_network('2001::/32')):
        raise ValueError('IPv6 transition address')
    return ip


def validate_url(url):
    if not isinstance(url, str) or len(url) > 2048 or not url.isascii() or re.search(r'[\x00-\x20\x7f\\#]', url):
        raise ValueError('invalid URL')
    try:
        p = urlsplit(url)
        host, port = p.hostname, p.port or 443
        if p.scheme != 'https' or not host or p.username is not None or p.password is not None or p.port == 0:
            raise ValueError('invalid URL')
        host = host.lower()
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            if not _HOST.fullmatch(host):
                raise ValueError('invalid host')
            authority = host
        else:
            public_ip(host)
            authority = '[' + host + ']' if ip.version == 6 else host
        # Exclude ambiguous authorities, including an empty/zero port.
        explicit = p.port is not None
        expected = authority + (':' + str(p.port) if explicit else '')
        if p.netloc.lower() != expected:
            raise ValueError('invalid authority')
        path = p.path or '/'
        if not path.startswith('/') or re.search(r'%(?![0-9a-fA-F]{2})', path + p.query):
            raise ValueError('invalid path')
        return host, port, path + ('?' + p.query if p.query else ''), 'https://' + expected + '/'
    except (ValueError, UnicodeError):
        raise ValueError('invalid URL') from None


def result(target):
    return {'mode': 'live', 'target': target, 'observed_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'http_status': None, 'tls': {'certificate': 'indeterminate', 'hostname': 'indeterminate',
                'protocol': None, 'not_before': None, 'not_after': None},
            'headers': {name: 'indeterminate' for name in _NAMES}, 'failure_code': 'unknown'}


def parse_head(data):
    end = data.find(b'\r\n\r\n')
    if end < 0 or end + 4 != len(data) or len(data) > _LIMIT:
        raise ValueError('incomplete headers')
    lines = data[:end].split(b'\r\n')
    if not re.fullmatch(rb'HTTP/1\.[01] [2-5][0-9]{2} [\x20-\x7e]*', lines[0]) or any(not _FIELD.fullmatch(line) for line in lines[1:]):
        raise ValueError('invalid headers')
    status = int(lines[0][9:12])
    fields = [(line.split(b':', 1)[0].lower(), line.split(b':', 1)[1].strip()) for line in lines[1:]]
    lengths = [v for k, v in fields if k == b'content-length']
    encodings = [v for k, v in fields if k == b'transfer-encoding']
    if (len(lengths) > 1 or any(not re.fullmatch(rb'[0-9]{1,19}', v) for v in lengths)
            or (status == 204 and (lengths or encodings))
            or len(encodings) > 1 or (encodings and (lengths or lines[0].startswith(b'HTTP/1.0 ')
                                                      or not _valid_transfer_encoding(encodings[0])))):
        raise ValueError('ambiguous headers')
    return status, {key: 'present' if any(k == name for k, _ in fields) else 'absent' for key, name in _NAMES.items()}


def exchange_connected(sock, host, authority, path, context, deadline, out):
    """HEAD on already-connected socket. Caller enforces destination policy."""
    def remaining():
        n = deadline - time.monotonic()
        if n <= 0:
            raise TimeoutError()
        return n
    if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
        raise ValueError('TLS verification required')
    sock.settimeout(remaining())
    with context.wrap_socket(sock, server_hostname=host, do_handshake_on_connect=False) as tls:
        tls.settimeout(remaining())
        tls.do_handshake()
        cert = tls.getpeercert()
        out['tls'] = {'certificate': 'verified', 'hostname': 'verified', 'protocol': tls.version(),
                      'not_before': cert.get('notBefore'), 'not_after': cert.get('notAfter')}
        tls.settimeout(remaining())
        tls.sendall(('HEAD ' + path + ' HTTP/1.1\r\nHost: ' + authority + '\r\nConnection: close\r\n\r\n').encode('ascii'))
        data = bytearray()
        while b'\r\n\r\n' not in data and len(data) <= _LIMIT:
            tls.settimeout(remaining())
            chunk = tls.recv(min(4096, _LIMIT + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        try:
            out['http_status'], out['headers'] = parse_head(bytes(data))
            out['failure_code'] = 'http_refused' if out['http_status'] >= 400 else 'none'
        except ValueError:
            out['failure_code'] = 'incomplete'


def observe(url, timeout=8):
    host, port, path, target = validate_url(url)
    out = result(target)
    deadline = time.monotonic() + timeout
    sock = None
    try:
        rows = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if not rows:
            raise ValueError('empty DNS')
        addresses = []
        for family, kind, _, _, addr in rows:
            if family not in (socket.AF_INET, socket.AF_INET6) or kind != socket.SOCK_STREAM or addr[1] != port:
                raise ValueError('invalid DNS')
            if family == socket.AF_INET6 and addr[3]:
                raise ValueError('scope')
            ip = public_ip(addr[0])
            if ip.version != (4 if family == socket.AF_INET else 6):
                raise ValueError('family mismatch')
            addresses.append((family, str(ip)))
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        family, address = addresses[0]
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(remaining)
        sock.connect((address, port))
        if public_ip(sock.getpeername()[0]) != ipaddress.ip_address(address) or sock.getpeername()[1] != port:
            raise ValueError('peer mismatch')
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_default_certs()
        exchange_connected(sock, host, target[8:-1], path, context, deadline, out)
    except TimeoutError:
        out['failure_code'] = 'timeout'
    except ValueError:
        out['failure_code'] = 'blocked'
    except (OSError, ssl.SSLError):
        out['failure_code'] = 'tls_or_transport'
    finally:
        if sock is not None:
            sock.close()
    return out
