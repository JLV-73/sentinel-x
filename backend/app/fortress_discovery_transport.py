"""Unwired experimental HTTPS GET; not an authorization or crawl boundary.

Only a small HTTP/1.x subset is accepted. The legacy get result contains no
response data; exchange returns sensitive, scope-checked navigation metadata
for internal use and must not be logged or exposed as a final result.
A self-delimited response ends at its framing boundary. Excess bytes already
read are rejected; bytes arriving later cannot be ruled out. The connection is
closed, never reused. Close-delimited bodies require authenticated TLS shutdown.
DNS is synchronous and cannot be interrupted; caller must supply a separately
confined worker before any activation. GET itself may have side effects.
"""
import ipaddress
from contextvars import ContextVar
import math
import re
import socket
import ssl
import time
import zlib
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from .fortress_live import public_ip, validate_url, _FIELD, _valid_transfer_encoding
from .fortress_discovery_a import _DANGEROUS
from .fortress_discovery_contract import PARTIAL_HEADER_NAMES

_MAX = 512 * 1024
_HEADERS = 32768
_PATH = re.compile(r'/[A-Za-z0-9._~/-]*\Z')
_CHUNK_LINE = re.compile(rb'''([0-9A-Fa-f]{1,16})(?:[ \t]*;[ \t]*[!#$%&'*+.^_`|~0-9A-Za-z-]+(?:[ \t]*=[ \t]*(?:[!#$%&'*+.^_`|~0-9A-Za-z-]+|"(?:[\x09\x20\x21\x23-\x5b\x5d-\x7e]|\\[\x09\x20-\x7e])*"))?)*\r\n''')
_diagnostic = ContextVar('discovery_diagnostic', default=None)


class _BudgetExceeded(ValueError):
    pass


class _DNSFailure(ValueError):
    pass


def capture_observed(url, max_bytes, timeout):
    """Capture only attested events; substituted exchanges are unknown."""
    event = {'phase': 'unknown', 'requests_sent': None, 'responses_received': None}
    token = _diagnostic.set(event)
    try:
        return exchange_observed(url, max_bytes, timeout), event
    finally:
        _diagnostic.reset(token)


def _target(url):
    if not isinstance(url, str) or '?' in url or '#' in url:
        raise ValueError()
    host, port, path, origin = validate_url(url)
    if (not _PATH.fullmatch(path) or path.startswith('//') or '//' in path
            or any(p in ('.', '..') for p in path.split('/'))
            or _DANGEROUS.search(path) or re.search(r'(?:^|/)api(?:/|$)', path, re.I)):
        raise ValueError()
    return host, port, path, origin[8:-1]


def _remaining(deadline):
    left = deadline - time.monotonic()
    if left <= 0:
        raise TimeoutError()
    return left


def _resolve(host, port):
    rows = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    if not rows:
        raise _DNSFailure()
    if len(rows) > 128:
        raise ValueError()
    addresses = []
    for family, kind, _, _, addr in rows:
        if family not in (socket.AF_INET, socket.AF_INET6) or kind != socket.SOCK_STREAM or addr[1] != port:
            raise ValueError()
        if family == socket.AF_INET6 and (len(addr) != 4 or addr[2] or addr[3]):
            raise ValueError()
        ip = public_ip(addr[0])
        if ip.version != (4 if family == socket.AF_INET else 6):
            raise ValueError()
        addresses.append((family, str(ip)))
    return addresses[0]


def _length_parts(tls, deadline, initial, length):
    part = initial
    received = 0
    while True:
        received += len(part)
        if received > length:
            raise ValueError()
        yield part
        if received == length:
            return
        tls.settimeout(_remaining(deadline))
        part = tls.recv(16384)
        if not part:
            raise ValueError()


def _close_parts(tls, deadline, initial):
    # Only SSLSocket with ragged EOF suppression disabled can distinguish a
    # TLS close_notify from an unclean TCP EOF. Never accept a generic stream.
    if not isinstance(tls, ssl.SSLSocket) or tls.suppress_ragged_eofs:
        raise ValueError()
    wire = 0
    part = initial
    while True:
        wire += len(part)
        if wire > _MAX:
            raise _BudgetExceeded()
        if part:
            yield part
        tls.settimeout(_remaining(deadline))
        part = tls.recv(min(16384, _MAX + 1 - wire))
        if not part:
            return  # SSL_ERROR_ZERO_RETURN: peer sent close_notify.


def _chunk_parts(tls, deadline, initial):
    # Trailers are rejected; wire budget includes all chunk framing.
    buf = bytearray(initial)
    wire = len(buf)
    def take(n):
        nonlocal wire
        while len(buf) < n:
            tls.settimeout(_remaining(deadline))
            part = tls.recv(16384)
            if not part:
                raise ValueError()
            wire += len(part)
            if wire > _MAX + _HEADERS:
                raise _BudgetExceeded()
            buf.extend(part)
        result = bytes(buf[:n])
        del buf[:n]
        return result
    while True:
        line = bytearray()
        while not line.endswith(b'\r\n'):
            line.extend(take(1))
            if len(line) > 4096:
                raise ValueError()
        match = _CHUNK_LINE.fullmatch(line)
        if not match:
            raise ValueError()
        length = int(match.group(1), 16)
        if length > _MAX:
            raise _BudgetExceeded()
        if not length:
            if take(2) != b'\r\n' or buf:
                raise ValueError()
            return
        while length:
            part = take(min(length, 16384))
            length -= len(part)
            yield part
        if take(2) != b'\r\n':
            raise ValueError()


def _read_response(tls, deadline, max_bytes=_MAX, project=False, base=None):
    data = bytearray()
    while b'\r\n\r\n' not in data:
        tls.settimeout(_remaining(deadline))
        part = tls.recv(min(4096, _HEADERS + 1 - len(data)))
        if not part:
            raise ValueError()
        data.extend(part)
        if len(data) > _HEADERS and b'\r\n\r\n' not in data[:_HEADERS]:
            raise ValueError()
    end = data.index(b'\r\n\r\n') + 4
    if end > _HEADERS:
        raise ValueError()
    lines = bytes(data[:end - 4]).split(b'\r\n')
    if not re.fullmatch(rb'HTTP/1\.[01] [2-5][0-9]{2} [\x20-\x7e]*', lines[0]) or any(not _FIELD.fullmatch(line) for line in lines[1:]):
        raise ValueError()
    event = _diagnostic.get()
    if event is not None:
        # Complete syntactically valid status line and fields, not full framing.
        event['responses_received'] = 1
    status = int(lines[0][9:12])
    fields = [(line.split(b':', 1)[0].lower(), line.split(b':', 1)[1].strip()) for line in lines[1:]]
    def attest_headers():
        if event is not None:
            event['_status'] = status
            names = {k for k, _ in fields}
            event['_partial_headers'] = {'present': [n for n in PARTIAL_HEADER_NAMES if n.encode('ascii') in names],
                                         'completeness': 'headers_validated_body_incomplete'}
    lengths = [v for k, v in fields if k == b'content-length']
    transfers = [v.lower() for k, v in fields if k == b'transfer-encoding']
    codings = [v.lower() for k, v in fields if k == b'content-encoding']
    if status in (204, 304):
        if (len(data) != end or (transfers and lengths)
                or (status == 204 and (lengths or transfers))
                or len(lengths) > 1 or any(not re.fullmatch(rb'[0-9]{1,19}', v) for v in lengths)
                or len(transfers) > 1 or (transfers and (lines[0].startswith(b'HTTP/1.0 ')
                                                       or not _valid_transfer_encoding(transfers[0])))):
            raise ValueError()
        _remaining(deadline)
        if project == 'observed':
            return status, 0, [], None, _evidence(status, 0, fields, full=True)['evidence'] if status == 204 else None, None
        if project == 'evidence':
            return _evidence(status, 0, fields)
        return (status, 0, [], None) if project else (status, 0)
    if (transfers not in ([], [b'chunked']) or (transfers and lengths)
            or len(codings) > 1 or (codings and codings[0] not in (b'identity', b'gzip'))):
        raise ValueError()
    if status == 205:
        if (codings or len(lengths) > 1 or (lengths and
                (not re.fullmatch(rb'[0-9]{1,10}', lengths[0]) or int(lengths[0]) != 0))):
            raise ValueError()
        attest_headers()
        if transfers:
            parts = _chunk_parts(tls, deadline, bytes(data[end:]))
        elif lengths:
            parts = _length_parts(tls, deadline, bytes(data[end:]), 0)
        else:
            parts = _close_parts(tls, deadline, bytes(data[end:]))
        for part in parts:
            if part:
                raise ValueError()
        _remaining(deadline)
        if event is not None:
            event.pop('_status', None)
            event.pop('_partial_headers', None)
        if project == 'observed':
            return status, 0, [], None, None, None
        if project == 'evidence':
            return _evidence(status, 0, fields)
        return (status, 0, [], None) if project else (status, 0)
    if not transfers and lengths and (len(lengths) != 1 or not re.fullmatch(rb'[0-9]{1,10}', lengths[0])):
        raise ValueError()
    length = int(lengths[0]) if lengths else None
    if project == 'observed' and status == 200 and length != 0:
        types = [v.lower() for k, v in fields if k == b'content-type']
        if types and (len(types) != 1 or not re.fullmatch(rb'text/html(?:\s*;\s*charset\s*=\s*utf-8)?', types[0])):
            raise ValueError()
    if length is not None and len(data) - end > length:
        raise ValueError()
    # Attest only after syntax and framing checks, before any body budget exit.
    attest_headers()
    if length is not None and length > _MAX:
        raise _BudgetExceeded()
    compressed = codings == [b'gzip']
    if not compressed and length is not None and length > max_bytes:
        raise _BudgetExceeded()
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS) if compressed else None
    decoded = bytearray()
    received = 0
    if transfers:
        parts = _chunk_parts(tls, deadline, bytes(data[end:]))
    elif length is not None:
        parts = _length_parts(tls, deadline, bytes(data[end:]), length)
    else:
        parts = _close_parts(tls, deadline, bytes(data[end:]))
    for part in parts:
        received += len(part)
        if compressed:
            decoded.extend(decoder.decompress(part, max_bytes + 1 - len(decoded)))
            if len(decoded) > max_bytes or decoder.unconsumed_tail or decoder.unused_data:
                if len(decoded) > max_bytes or decoder.unconsumed_tail:
                    raise _BudgetExceeded()
                raise ValueError()
        else:
            decoded.extend(part)
            if len(decoded) > max_bytes:
                raise _BudgetExceeded()
    _remaining(deadline)
    if compressed and not decoder.eof:
        raise ValueError()
    if event is not None:
        event.pop('_status', None)
        event.pop('_partial_headers', None)
    size = len(decoded)
    _remaining(deadline)
    if not project:
        return status, size
    if project == 'lab_response':
        return status, size, fields, bytes(decoded)
    if project == 'evidence':
        return _evidence(status, size, fields)
    locations = [v for k, v in fields if k == b'location']
    location = None
    if len(locations) == 1:
        location = _reference(locations[0].decode('ascii', 'strict'), base)
    content_types = [v.lower() for k, v in fields if k == b'content-type']
    links = []
    resources = None
    is_html = len(content_types) == 1 and re.fullmatch(rb'text/html(?:\s*;\s*charset\s*=\s*utf-8)?', content_types[0])
    if status == 200 and size and not is_html:
        raise ValueError()
    if status == 200 and is_html:
        parser = _Links(base, report_excluded=project == 'observed')
        parser.feed(bytes(decoded).decode('utf-8', 'strict'))
        parser.close()
        links = parser.links
        resources = parser.resources
    if project == 'observed':
        return status, size, links, location, _evidence(status, size, fields, full=True)['evidence'] if status == 200 or status >= 300 else None, resources
    return status, size, links, location


def _evidence(status, size, fields, *, full=False):
    """Project response headers, without retaining their raw values."""
    from datetime import datetime, timezone
    from .fortress_discovery_intelligence import analyze_pages
    relevant = {b'strict-transport-security', b'content-security-policy',
                b'content-security-policy-report-only', b'set-cookie',
                b'x-content-type-options', b'referrer-policy', b'permissions-policy'}
    headers = [(k.decode('ascii'), v.decode('ascii')) for k, v in fields if k in relevant]
    page = {'route': '/page', 'observed_at': datetime.now(timezone.utc).isoformat(),
            'status': status, 'complete': True, 'headers': headers}
    observations = analyze_pages([page])['pages'][0]['observations']
    evidence = observations if full or observations is None else {k: observations[k] for k in
                   ('hsts', 'csp', 'csp_report_only', 'cookies')}
    return {'status': status, 'decoded_bytes': size, 'evidence': evidence}


def _reference(value, base):
    try:
        if not value or len(value) > 2048 or not value.isascii() or re.search(r'[\x00-\x20\x7f\\%?#]', value):
            return None
        raw = urlsplit(value)
        if any(p in ('.', '..') for p in raw.path.split('/')) or '//' in raw.path:
            return None
        resolved = urljoin(base, value)
        source = _target(base)
        target = _target(resolved)
        if target[:2] != source[:2]:
            return None
        return value
    except (ValueError, UnicodeError):
        return None


class _Links(HTMLParser):
    def __init__(self, base, *, report_excluded=False):
        super().__init__(convert_charrefs=True)
        self.base, self.links, self.count = base, [], 0
        self.report_excluded = report_excluded
        self.resources = {'script': 0, 'stylesheet': 0}

    def handle_starttag(self, tag, attrs):
        # Count tags only; resource values are never retained or resolved.
        if self.report_excluded and tag in ('script', 'link'):
            values = [v for k, v in attrs if k == ('src' if tag == 'script' else 'href')]
            rel = [v for k, v in attrs if k == 'rel']
            if (len(values) == 1 and isinstance(values[0], str) and values[0].strip()
                    and (tag == 'script' or (len(rel) == 1 and isinstance(rel[0], str)
                         and 'stylesheet' in re.split(r'[\t\n\f\r ]+', rel[0].lower())))):
                kind = 'script' if tag == 'script' else 'stylesheet'
                self.resources[kind] += 1
                if self.resources[kind] > 1000:
                    raise ValueError()
        if tag != 'a':
            return
        values = [v for k, v in attrs if k == 'href']
        if not values:
            return
        self.count += 1
        if self.count > 1000 or len(values) != 1 or not isinstance(values[0], str):
            raise ValueError()
        value = values[0]
        link = _reference(value, self.base)
        if link is None:
            if self.report_excluded:
                self.links.append(None)
                return
            # Ignore only valid HTTP(S) absolute or network-path links to
            # another origin; never return or resolve them over the network.
            try:
                raw = urlsplit(value)
                if (raw.scheme in ('http', 'https', '') and raw.netloc
                        and '?' not in value and '#' not in value):
                    candidate = 'https://' + raw.netloc + raw.path
                    target = _target(candidate)
                    if raw.scheme == 'http' or target[:2] != _target(self.base)[:2]:
                        return
            except (ValueError, UnicodeError):
                pass
            raise ValueError()
        self.links.append(link)


def get(url, timeout=8):
    """Return closed status/size metadata, never URLs, headers, body or errors.

    No automatic redirects, credentials, cookies, proxies, retries or queries.
    A single request has fixed wire/decoded limits. No aggregate crawl budget is
    provided. Timeouts on socket operations do not bound synchronous DNS.
    """
    return _exchange(url, _MAX, timeout, False)


def exchange(url, max_bytes, timeout):
    """Internal crawl contract; returns {} on failure, never response bodies.

    Returned references are sensitive internal metadata, not report data.
    The caller must separately enforce its scope and must not log this result.
    """
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
        return {}
    return _exchange(url, max_bytes, min(timeout, 30), True)


def exchange_observed(url, max_bytes, timeout):
    """Experimental internal projection; not connected to the live API.

    Navigation references remain sensitive and must not leave the worker.
    Observations and references derive from the same completely framed response.
    """
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
        return {}
    if _diagnostic.get() is not None:
        return _exchange(url, max_bytes, min(timeout, 30), 'observed')
    token = _diagnostic.set({})
    try:
        return _exchange(url, max_bytes, min(timeout, 30), 'observed')
    finally:
        _diagnostic.reset(token)


def _exchange(url, max_bytes, timeout, project):
    sock = None
    partial_status = None
    partial_headers = None
    event = _diagnostic.get()
    phase = 'scope'
    if event is not None:
        event.update(phase='unknown', requests_sent=0, responses_received=0)
    try:
        if type(max_bytes) is not int or not 1 <= max_bytes <= _MAX:
            raise ValueError()
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 30:
            raise ValueError()
        host, port, path, authority = _target(url)
        deadline = time.monotonic() + timeout
        phase = 'dns'
        family, address = _resolve(host, port)
        _remaining(deadline)
        phase = 'connect'
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(_remaining(deadline))
        sock.connect((address, port))
        peer = sock.getpeername()
        phase = 'scope'
        if public_ip(peer[0]) != ipaddress.ip_address(address) or peer[1] != port:
            raise ValueError()
        phase = 'tls'
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.load_default_certs()
        sock.settimeout(_remaining(deadline))
        with context.wrap_socket(sock, server_hostname=host, do_handshake_on_connect=False,
                                 suppress_ragged_eofs=False) as tls:
            sock = None
            tls.settimeout(_remaining(deadline))
            tls.do_handshake()
            if (event is not None and isinstance(tls, ssl.SSLSocket)
                    and context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname):
                from datetime import datetime, timezone
                certificate = tls.getpeercert()
                if certificate:
                    expiry = None
                    try:
                        expiry = datetime.fromtimestamp(ssl.cert_time_to_seconds(certificate['notAfter']), timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                    except (KeyError, ValueError, TypeError, OverflowError, OSError):
                        pass
                    version = tls.version()
                    event['_tls'] = {'version': version if version in ('TLSv1.2', 'TLSv1.3') else 'unknown',
                                     'certificate_verified': True, 'hostname_verified': True, 'not_after': expiry}
            tls.settimeout(_remaining(deadline))
            phase = 'connect'
            if event is not None:
                event['requests_sent'] = None  # A failed sendall may be partial.
            tls.sendall(('GET ' + path + ' HTTP/1.1\r\nHost: ' + authority + '\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n').encode('ascii'))
            if event is not None:
                event['requests_sent'] = 1
            phase = 'parse'
            result = _read_response(tls, deadline, max_bytes, project, url)
        _remaining(deadline)
        if event is not None:
            event['phase'] = 'none'
        if project:
            if project == 'observed':
                status, size, links, location, observations, resources = result
                return {'status': status, 'decoded_bytes': size, 'links': links,
                        'location': location, 'observations': observations, 'resources': resources}
            status, size, links, location = result
            return {'status': status, 'decoded_bytes': size, 'links': links, 'location': location}
        status, size = result
        return {'error': None, 'status': status, 'decoded_bytes': size}
    except TimeoutError:
        error = 'timeout'
        phase = 'timeout'
    except ssl.SSLError:
        error = 'transport'
        if phase != 'tls':
            phase = 'unknown'
    except _BudgetExceeded:
        error = 'blocked'
        phase = 'budget'
    except _DNSFailure:
        error = 'blocked'
        phase = 'dns'
    except (ValueError, UnicodeError):
        error = 'blocked'
        if phase == 'dns':
            phase = 'scope'
    except OSError:
        error = 'transport'
        if phase not in ('dns', 'connect'):
            phase = 'unknown'
    except Exception:
        error = 'transport'
        phase = 'unknown'
    finally:
        if event is not None:
            partial_status = event.pop('_status', None)
            partial_headers = event.pop('_partial_headers', None)
        if event is not None and event['phase'] != 'none':
            event['phase'] = phase
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
    if project == 'observed' and partial_status is not None:
        return {'status': partial_status, 'incomplete': True, 'partial_headers': partial_headers}
    return {} if project else {'error': error, 'status': None, 'decoded_bytes': None}
