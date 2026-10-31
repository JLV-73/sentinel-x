"""Fail-closed scoped HTTP transport. Dependencies are injectable only by trusted code."""
from dataclasses import dataclass
import http.client
import ipaddress
import re
import socket
import ssl
import threading
import time
from functools import wraps
from urllib.parse import urlsplit, urljoin, urlencode


class TransportError(ValueError):
    """A request was refused or did not complete safely."""


class _StrictHeaderStream:
    """Validate exactly the bytes HTTPResponse consumes, before it derives facts."""
    def __init__(self, stream):
        self.stream = stream
        self.checking = True
        self.expect_status = True
        self.complete = False
        self.total = 0
        self.content_length = False


    def readline(self, limit=-1):
        if not self.checking:
            return self.stream.readline(limit)
        # http.client passes its own bounded line limit; never permit unbounded reads.
        if limit < 0 or limit > 65537:
            limit = 65537
        line = self.stream.readline(limit)
        self.total += len(line)
        if (self.total > 131072 or not line.endswith(b'\r\n') or
            b'\r' in line[:-2] or b'\n' in line[:-2]):
            raise TransportError('invalid header framing')
        content = line[:-2]
        if self.expect_status:
            if not re.fullmatch(rb'HTTP/1\.[01] [0-9]{3}(?: [\x20-\x7e\x80-\xff\t]*)?', content):
                raise TransportError('invalid status line')
            self.expect_status = False
            self.complete = False
            self.content_length = False
        elif not content:
            self.complete = True
            self.expect_status = True  # http.client may consume a 100 response first
        else:
            name, separator, value = content.partition(b':')
            if (not separator or not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) or
                any(c < 32 and c != 9 or c == 127 for c in value)):
                raise TransportError('invalid header field')
            name = name.lower()
            if name == b'content-length':
                if self.content_length or not re.fullmatch(rb'[0-9]+', value.strip(b' \t')):
                    raise TransportError('invalid content length')
                self.content_length = True
            elif name == b'transfer-encoding':
                # http.client's permissive chunk framing is not validated here.
                raise TransportError('transfer encoding unsupported')
        return line

    def __getattr__(self, name):
        return getattr(self.stream, name)


class _HeaderCheckedSocket:
    def __init__(self, sock):
        self.sock = sock
        self.stream = None

    def makefile(self, mode):
        self.stream = _StrictHeaderStream(self.sock.makefile(mode))
        return self.stream


@dataclass(frozen=True)
class Scope:
    origin: tuple[str, str, int]
    routes: frozenset[str]


@dataclass(frozen=True)
class Response:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes
    url: str
    blocked: bool
    cookies: tuple[int, int, int, int, int] = (0, 0, 0, 0, 0)
    reflected: bool = False
    witness_match: bool = False
    indeterminate: bool = False
    baseline_marker: bool = False
    baseline_first: bool = False
    baseline_second: bool = False
    headers_complete: bool = True


_SECURITY_HEADERS = {
    'hsts': 'strict-transport-security',
    'csp': 'content-security-policy',
    'x_content_type_options': 'x-content-type-options',
    'referrer_policy': 'referrer-policy',
    'permissions_policy': 'permissions-policy',
}


def _header_facts(headers, complete):
    """Classify a deliberately narrow syntax subset, never policy effectiveness."""
    result = {}
    for name, header in _SECURITY_HEADERS.items():
        values = [v for k, v in headers if k.lower() == header]
        if not complete or len(values) > 1:
            result[name] = 'unknown'
        elif not values:
            result[name] = 'absent'
        else:
            value = values[0].strip(' \t')
            if not value:
                result[name] = 'invalid'
                continue
            if len(value) > 4096 or not value.isascii() or any(ord(c) < 32 or ord(c) == 127 for c in value):
                result[name] = 'unknown'
                continue
            v = value.lower()
            recognized = (
                (name == 'hsts' and re.fullmatch(r'max-age=[0-9]{1,10}(?:;\s*includesubdomains)?(?:;\s*preload)?', v)) or
                (name == 'csp' and v == "default-src 'none'") or
                (name == 'x_content_type_options' and v == 'nosniff') or
                (name == 'referrer_policy' and v in ('no-referrer', 'no-referrer-when-downgrade', 'origin', 'origin-when-cross-origin', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin', 'unsafe-url')) or
                (name == 'permissions_policy' and v in ('camera=()', 'microphone=()', 'geolocation=()'))
            )
            result[name] = 'present' if recognized else 'unknown'
    return result


def _cookie_facts(headers):
    count = secure = httponly = samesite = indeterminate = 0
    for key, value in headers:
        if key.lower() != 'set-cookie':
            continue
        count += 1
        parts = value.split(';')
        if len(value) > 8192 or '=' not in parts[0] or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", parts[0].split('=', 1)[0].strip()) or any(ord(c) < 32 or ord(c) == 127 for c in value):
            indeterminate += 1
            continue
        attributes = [p.strip().lower() for p in parts[1:]]
        names = [x.split('=', 1)[0].strip() for x in attributes]
        # Commas/quotes and duplicate or malformed attributes are conservative unknowns,
        # including legitimate Expires dates whose interpretation varies by client.
        if ',' in value or '"' in value or len(names) != len(set(names)) or any(not x for x in names) or any(x.startswith(('secure=', 'httponly=')) for x in attributes):
            indeterminate += 1
            continue
        same = [x for x in attributes if x.split('=', 1)[0].strip() == 'samesite']
        if len(same) > 1 or (same and same[0] not in ('samesite=strict', 'samesite=lax', 'samesite=none')):
            indeterminate += 1
            continue
        secure += int('secure' not in attributes)
        httponly += int('httponly' not in attributes)
        samesite += int(not any(x in ('samesite=strict', 'samesite=lax', 'samesite=none') for x in attributes))
    return count, secure, httponly, samesite, indeterminate


def _parse(url: str):
    if not isinstance(url, str) or not url or len(url) > 4096 or not url.isascii():
        raise TransportError('invalid URL')
    if any(ord(c) <= 32 or ord(c) >= 127 for c in url) or any(c in url for c in '%\\#'):
        raise TransportError('ambiguous URL')
    invalid_authority = False
    try:
        p = urlsplit(url)
        port = p.port
    except ValueError:
        invalid_authority = True
    if invalid_authority:
        raise TransportError('invalid authority')
    if p.scheme not in ('http', 'https') or not p.netloc or p.username is not None or p.password is not None:
        raise TransportError('invalid authority')
    if '@' in p.netloc or not p.hostname or p.hostname.endswith('.'):
        raise TransportError('invalid host')
    host = p.hostname
    if host == 'localhost' or host.endswith('.localhost'):
        raise TransportError('local host')
    if host != host.lower():
        raise TransportError('invalid host')
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        addr = None
    if addr is None:
        if ':' in host or len(host) > 253 or not re.fullmatch(r'[a-z0-9.-]+', host):
            raise TransportError('invalid host')
        labels = host.split('.')
        if any(not x or len(x) > 63 or x[0] == '-' or x[-1] == '-' for x in labels):
            raise TransportError('invalid host')
        # Numeric and mixed numeric address forms can be interpreted differently by resolvers.
        if all(re.fullmatch(r'(?:[0-9]+|0x[0-9a-f]+)', x) for x in labels):
            raise TransportError('ambiguous address')
        if labels[-1].isdigit() or any(x.startswith('0x') for x in labels):
            raise TransportError('ambiguous host')
    else:
        if str(addr) != host or not _public(addr):
            raise TransportError('nonpublic address')
    effective = port if port is not None else (443 if p.scheme == 'https' else 80)
    if effective not in (80, 443):
        raise TransportError('disallowed port')
    # Reject noncanonical authorities including leading zero and empty ports.
    expected_host = f'[{host}]' if ':' in host else host
    if p.netloc != expected_host and p.netloc != f'{expected_host}:{effective}':
        raise TransportError('noncanonical authority')
    path = p.path or '/'
    if not path.startswith('/') or '//' in path or ';' in path or any(s in ('.', '..') for s in path.split('/')):
        raise TransportError('ambiguous path')
    if p.query:
        names = {}
        for item in p.query.split('&'):
            key = item.split('=', 1)[0]
            if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,63}', key):
                raise TransportError('invalid query')
            if re.search(r'pass|token|secret|auth|session|cookie|credential|api.?key', key, re.I):
                raise TransportError('sensitive query')
            if any(c in item for c in '?;'):
                raise TransportError('ambiguous query')
            normalized = key.lower().replace('.', '_')
            if normalized in names and names[normalized] != key:
                raise TransportError('ambiguous query')
            names[normalized] = key
    canonical = f'{p.scheme}://{expected_host}:{effective}{path}' + (f'?{p.query}' if p.query else '')
    return (p.scheme, host, effective), canonical, path + (f'?{p.query}' if p.query else '')


def _public(addr):
    if not addr.is_global or addr.is_multicast or addr.is_unspecified or addr.is_reserved or addr.is_loopback or addr.is_link_local or addr.is_private:
        return False
    if isinstance(addr, ipaddress.IPv4Address):
        # ipaddress.is_global in Python 3.11 includes anycast and deprecated relay space.
        if any(addr in ipaddress.ip_network(net) for net in ('192.0.0.0/24', '192.88.99.0/24')):
            return False
    if isinstance(addr, ipaddress.IPv6Address):
        # Only ordinary global unicast, excluding IETF protocol assignments and 6to4.
        if addr not in ipaddress.ip_network('2000::/3') or any(addr in ipaddress.ip_network(net) for net in ('2001::/23', '2002::/16', '3fff::/20')):
            return False
        if addr.ipv4_mapped or addr.sixtofour or addr.teredo or addr.scope_id:
            return False
    return True


def validate_scope(target: str, extra: list[str]) -> Scope:
    if not isinstance(extra, list) or len(extra) > 3:
        raise TransportError('invalid routes')
    origin, route, _ = _parse(target)
    routes = {route}
    for value in extra:
        other, canonical, _ = _parse(value)
        if other != origin:
            raise TransportError('cross-origin scope')
        routes.add(canonical)
    return Scope(origin, frozenset(routes))


def _halt_on_uncertainty(method):
    """Serialize outcome and halt as one operation, including validation failures."""
    @wraps(method)
    def guarded(self, *args, **kwargs):
        with self._request_lock:
            if self.blocked:
                return {'outcome': 'error'}
            try:
                result = method(self, *args, **kwargs)
            except Exception:
                self.blocked = True
                return {'outcome': 'error'}
            if result.get('outcome') != 'ok':
                self.blocked = True
            return result
    return guarded


class SafeTransport:
    """One instance per audit. No redirects, cookies, proxies, retries or auth by library.

    resolver/socket_factory/tls_context are trusted unit-test injection points, not API input.
    Deadlines are cooperative; a blocking resolver or slow-drip buffered read can exceed them.
    """
    def __init__(self, scope: Scope, *, resolver=socket.getaddrinfo, socket_factory=socket.socket,
                 tls_context=None, timeout=5.0, deadline=45.0, max_bytes=262144, max_requests=30, approved_probes=None, scoped_probes=None, cors_routes=None, allowed_methods=None):
        if not isinstance(scope, Scope) or not (0 < timeout <= 10 and 0 < deadline <= 45 and 0 < max_bytes <= 262144 and 0 < max_requests <= 30):
            raise TransportError('invalid transport configuration')
        self.scope, self.resolver, self.socket_factory = scope, resolver, socket_factory
        # Trusted service supplies an immutable exact route/method policy. Legacy
        # internal callers omit it; that compatibility is not API authorization.
        if allowed_methods is not None:
            if (type(allowed_methods) is not frozenset or not allowed_methods or
                any(type(pair) is not tuple or len(pair) != 2 or
                    pair[0] not in scope.routes or pair[1] != 'GET' for pair in allowed_methods) or
                approved_probes is not None or scoped_probes is not None or cors_routes is not None):
                raise TransportError('invalid method policy')
        self._allowed_methods = allowed_methods
        self.tls_context = tls_context
        self.timeout, self.deadline, self.max_bytes, self.max_requests = timeout, deadline, max_bytes, max_requests
        self.started = time.monotonic()
        self.count = 0
        self.blocked = False
        self._request_lock = threading.RLock()
        self._cors_routes = set()
        if cors_routes is not None:
            if not isinstance(cors_routes, (set, frozenset, list, tuple)) or len(cors_routes) > 4:
                raise TransportError('invalid CORS approvals')
            for route in cors_routes:
                origin, canonical, _ = _parse(route)
                if '?' in route or origin != scope.origin or canonical not in scope.routes:
                    raise TransportError('invalid CORS approvals')
                self._cors_routes.add(canonical)
        self._scoped_probes = set()
        if scoped_probes is not None:
            if not isinstance(scoped_probes, (set, frozenset, list, tuple)) or len(scoped_probes) > 64:
                raise TransportError('invalid scoped approvals')
            normalized_approvals = {}
            for item in scoped_probes:
                if not isinstance(item, tuple) or len(item) != 3:
                    raise TransportError('invalid scoped approvals')
                route, key, kind = item
                origin, canonical, _ = _parse(route)
                if ('?' in route or origin != scope.origin or canonical not in scope.routes
                    or not isinstance(key, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,63}', key)
                    or re.search(r'pass|token|secret|auth|session|cookie|credential|api.?key', key, re.I)
                    or kind not in ('reflection', 'witness')):
                    raise TransportError('invalid scoped approvals')
                normalized = (canonical, key.lower().replace('.', '_'))
                if normalized in normalized_approvals and normalized_approvals[normalized] != key:
                    raise TransportError('ambiguous scoped approvals')
                normalized_approvals[normalized] = key
                self._scoped_probes.add((canonical, key, kind))
        self._approved_probes = {}
        if approved_probes is not None:
            if not isinstance(approved_probes, dict) or len(approved_probes) > 4:
                raise TransportError('invalid probe approvals')
            for url, keys in approved_probes.items():
                origin, canonical, _ = _parse(url)
                if origin != scope.origin or canonical not in scope.routes or not isinstance(keys, list) or len(keys) > 16:
                    raise TransportError('invalid probe approvals')
                for key in keys:
                    if not isinstance(key, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,63}', key) or re.search(r'pass|token|secret|auth|session|cookie|credential|api.?key', key, re.I):
                        raise TransportError('invalid probe approvals')
                    query = urlsplit(canonical).query
                    if key not in [item.split('=', 1)[0] for item in query.split('&') if item]:
                        raise TransportError('invalid probe approvals')
                self._approved_probes[canonical] = frozenset(keys)

    def _remaining(self):
        left = self.deadline - (time.monotonic() - self.started)
        if left <= 0:
            raise TransportError('deadline exceeded')
        return min(self.timeout, left)

    @_halt_on_uncertainty
    def observe(self, method: str, url: str):
        return self._observe(method, url, False)

    @_halt_on_uncertainty
    def observe_headers(self, method: str, url: str):
        """Return bounded derived facts; optional header enums do not assert protection.

        If the result omits security_headers (including errors), treat all as unknown.
        request() is internal and unsafe to expose.
        """
        return self._observe(method, url, True)

    def _observe(self, method, url, include_security_headers):
        try:
            before = self.count
            response = self.request(method, url)
            facts = dict(zip(('count', 'missing_secure', 'missing_httponly', 'missing_samesite', 'indeterminate'), response.cookies))
            result = {'outcome': 'blocked' if response.blocked else 'indeterminate' if response.indeterminate else 'ok', 'cookies': facts}
            if include_security_headers:
                result['security_headers'] = _header_facts(response.headers, not response.blocked and not response.indeterminate and response.headers_complete and self.count - before == 1)
            # Preserve the existing direct-response observer contract.
            if self.count - before > 1:
                result['redirected'] = True
            return result
        except Exception:
            pass
        return {'outcome': 'error'}

    @_halt_on_uncertainty
    def observe_scoped_baseline(self, url: str, key: str, kind: str):
        """Literal matches only; false does not exclude transformed signals."""
        try:
            origin, canonical, path = _parse(url)
            if '?' in url or origin != self.scope.origin or (canonical, key, kind) not in self._scoped_probes:
                return {'outcome': 'error'}
            with self._request_lock:
                before = self.count
                try:
                    response = self._request_locked('GET', url, None, (path, 'baseline'))
                except Exception:
                    if self.count > before:
                        self.blocked = True
                    raise
            if response.blocked or response.indeterminate:
                return {'outcome': 'blocked' if response.blocked else 'indeterminate'}
            return {'outcome': 'ok' if response.status == 200 else 'indeterminate',
                    'status': response.status, 'literal_marker_observed': response.baseline_marker,
                    'literal_first_witness_observed': response.baseline_first, 'literal_second_witness_observed': response.baseline_second}
        except Exception:
            return {'outcome': 'error'}

    @_halt_on_uncertainty
    def observe_cors(self, method: str, url: str):
        """Return only bounded CORS facts for an approved route and fixed origin."""
        try:
            origin, canonical, path = _parse(url)
            if method not in ('GET', 'OPTIONS') or '?' in url or origin != self.scope.origin or canonical not in self._cors_routes:
                return {'outcome': 'error'}
            headers = {'Origin': 'https://fortress-origin.invalid'}
            if method == 'OPTIONS':
                headers['Access-Control-Request-Method'] = 'GET'
            with self._request_lock:
                before = self.count
                try:
                    response = self._request_locked(method, url, headers, (path, 'cors'))
                except Exception:
                    if self.count > before:
                        self.blocked = True
                    raise
            if response.blocked or response.indeterminate:
                return {'outcome': 'blocked' if response.blocked else 'indeterminate'}
            values = [v.strip() for k, v in response.headers if k.lower() == 'access-control-allow-origin']
            acao = 'absent' if not values else 'match' if values == ['https://fortress-origin.invalid'] else 'wildcard' if values == ['*'] else 'other'
            credentials = [v.strip() for k, v in response.headers if k.lower() == 'access-control-allow-credentials']
            return {'outcome': 'ok' if response.status == 200 else 'indeterminate', 'status': response.status, 'acao': acao, 'acac': credentials == ['true']}
        except Exception:
            return {'outcome': 'error'}

    @_halt_on_uncertainty
    def observe_scoped_probe(self, url: str, key: str, kind: str, *, witness='first'):
        """Probe a query-free approved route with an internally generated inert value."""
        try:
            origin, canonical, path = _parse(url)
            if ('?' in url or origin != self.scope.origin or (canonical, key, kind) not in self._scoped_probes
                or witness not in ('first', 'second') or (kind != 'witness' and witness != 'first')):
                return {'outcome': 'error'}
            value = 'FORTRESSINERT2026' if kind == 'reflection' else {'first': 'https://example.invalid/', 'second': 'https://second.invalid/'}[witness]
            probe_path = path + '?' + urlencode({key: value})
            with self._request_lock:
                before = self.count
                try:
                    response = self._request_locked('GET', url, None, (probe_path, kind, value))
                except Exception:
                    if self.count > before:
                        self.blocked = True
                    raise
            if response.blocked or response.indeterminate:
                return {'outcome': 'blocked' if response.blocked else 'indeterminate'}
            return {'outcome': 'indeterminate', 'evidence': 'single_raw_observation_not_confirmation',
                    'status': response.status, 'reflected': response.reflected, 'witness_match': response.witness_match}
        except Exception:
            return {'outcome': 'error'}

    @_halt_on_uncertainty
    def observe_witness_attribution(self, url: str, key: str):
        """No causal conclusion: fixed responses cannot eliminate sequence effects."""
        try:
            with self._request_lock:
                baseline = self.observe_scoped_baseline(url, key, 'witness')
                if (baseline.get('outcome') != 'ok' or baseline.get('status') != 200 or
                    any(baseline.get(name) is True for name in ('literal_marker_observed', 'literal_first_witness_observed', 'literal_second_witness_observed'))):
                    return {'outcome': 'indeterminate'}
                # A single witness result is indeterminate even when it matches.
                # The guard latches the halt before any possible second request.
                self.observe_scoped_probe(url, key, 'witness', witness='first')
                return {'outcome': 'indeterminate'}
        except Exception:
            return {'outcome': 'error'}

    @_halt_on_uncertainty
    def observe_probe(self, url: str, key: str, kind: str):
        """One explicitly approved GET mutation; never follow any redirect."""
        try:
            origin, canonical, path = _parse(url)
            if origin != self.scope.origin or key not in self._approved_probes.get(canonical, ()) or kind not in ('reflection', 'witness'):
                return {'outcome': 'error'}
            base, _, query = path.partition('?')
            items = query.split('&') if query else []
            matches = [i for i, item in enumerate(items) if item.split('=', 1)[0] == key]
            if len(matches) > 1:
                return {'outcome': 'error'}
            value = 'FORTRESSINERT2026' if kind == 'reflection' else 'https%3A%2F%2Fexample.invalid%2F'
            if matches:
                items[matches[0]] = key + '=' + value
            else:
                items.append(key + '=' + value)
            probe_path = base + '?' + '&'.join(items)
            with self._request_lock:
                before = self.count
                try:
                    response = self._request_locked('GET', url, None, (probe_path, kind))
                except Exception:
                    if self.count > before:
                        self.blocked = True
                    raise
            if response.blocked or response.indeterminate:
                return {'outcome': 'blocked' if response.blocked else 'indeterminate'}
            return {'outcome': 'indeterminate', 'evidence': 'single_raw_observation_not_confirmation',
                    'reflected': response.reflected, 'witness_match': response.witness_match}
        except Exception:
            pass
        return {'outcome': 'error'}

    def request(self, method: str, url: str, headers: dict[str, str] | None = None) -> Response:
        with self._request_lock:
            try:
                return self._request_locked(method, url, headers)
            except Exception:
                # Even a pre-network rejection ends this audit's request stream.
                self.blocked = True
            raise TransportError('request failed')

    def _request_locked(self, method: str, url: str, headers: dict[str, str] | None = None, probe=None) -> Response:
        if self.blocked:
            raise TransportError('transport halted')
        if method not in ('GET', 'HEAD', 'OPTIONS'):
            raise TransportError('invalid method')
        if self._allowed_methods is not None and (probe is not None or headers):
            raise TransportError('advanced observation disabled')
        supplied = headers or {}
        if not isinstance(supplied, dict):
            raise TransportError('invalid headers')
        clean = {}
        for key, value in supplied.items():
            if not isinstance(key, str) or key.lower() not in ('origin', 'access-control-request-method', 'access-control-request-headers') or not isinstance(value, str) or not value.isascii() or len(value) > 512 or any(ord(c) < 32 or ord(c) == 127 for c in value):
                raise TransportError('unsafe header')
            if key.lower() in clean:
                raise TransportError('duplicate header')
            clean[key.lower()] = value
        current = url
        for _ in range(31):
            origin, canonical, path = _parse(current)
            if origin != self.scope.origin or canonical not in self.scope.routes:
                raise TransportError('outside scope')
            if self._allowed_methods is not None and (canonical, method) not in self._allowed_methods:
                raise TransportError('method not authorized for route')
            if probe is not None:
                path = probe[0]
            if self.count >= self.max_requests:
                raise TransportError('request budget exhausted')
            self._remaining()
            # Count before DNS, including failures; no retry is implicit.
            self.count += 1
            scheme, host, port = origin
            network_failure = False
            try:
                answers = self.resolver(host, port, type=socket.SOCK_STREAM)
                self._remaining()
                if not answers:
                    raise TransportError('empty DNS')
                addresses = []
                for family, socktype, proto, _, sockaddr in answers:
                    if family not in (socket.AF_INET, socket.AF_INET6) or socktype != socket.SOCK_STREAM:
                        raise TransportError('invalid DNS answer')
                    ip = ipaddress.ip_address(sockaddr[0])
                    if not _public(ip) or sockaddr[1] != port or (family == socket.AF_INET) != (ip.version == 4) or (family == socket.AF_INET6 and (len(sockaddr) < 4 or sockaddr[3] != 0)):
                        raise TransportError('unsafe DNS answer')
                    addresses.append((family, proto, sockaddr, ip))
                family, proto, sockaddr, ip = addresses[0]
                sock = self.socket_factory(family, socket.SOCK_STREAM, proto)
                try:
                    sock.settimeout(self._remaining())
                    sock.connect(sockaddr)
                    peer = sock.getpeername()
                    if ipaddress.ip_address(peer[0]) != ip or peer[1] != port:
                        raise TransportError('peer mismatch')
                    if scheme == 'https':
                        context = self.tls_context or ssl.create_default_context()
                        if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
                            raise TransportError('TLS verification required')
                        sock.settimeout(self._remaining())
                        sock = context.wrap_socket(sock, server_hostname=host)
                    sock.settimeout(self._remaining())
                    authority = f'[{host}]' if ':' in host else host
                    if port != (443 if scheme == 'https' else 80):
                        authority += f':{port}'
                    lines = [f'{method} {path} HTTP/1.1', f'Host: {authority}', 'Connection: close', 'Accept-Encoding: identity']
                    lines.extend(f'{k}: {v}' for k, v in clean.items())
                    sock.sendall(('\r\n'.join(lines) + '\r\n\r\n').encode('ascii'))
                    sock.settimeout(self._remaining())
                    checked_sock = _HeaderCheckedSocket(sock)
                    response = http.client.HTTPResponse(checked_sock, method=method)
                    response.begin()
                    if not checked_sock.stream.complete:
                        raise TransportError('incomplete headers')
                    checked_sock.stream.checking = False
                    self._remaining()
                    raw_headers = response.getheaders()
                    if response.status in (401, 403, 429) or any(
                        k.lower() in ('cf-mitigated', 'x-sucuri-block', 'retry-after') for k, _ in raw_headers
                    ):
                        self.blocked = True
                        return Response(response.status, (), b'', '', True)
                    if response.status == 206 or not (200 <= response.status < 300 or response.status in (301, 302, 303, 307, 308)):
                        self.blocked = True
                        return Response(response.status, (), b'', '', False, indeterminate=True)
                    if response.status in (301, 302, 303, 307, 308) and not response.getheader('Location'):
                        self.blocked = True
                        return Response(response.status, (), b'', '', False, indeterminate=True)
                    if response.getheader('Content-Encoding', 'identity').lower() not in ('', 'identity'):
                        raise TransportError('compressed response refused')
                    body = bytearray()
                    signatures = (b'captcha', b'cloudflare challenge', b'cf-mitigated', b'access denied', b'blocked by waf', b'challenge-platform')
                    carry = b''
                    while True:
                        sock.settimeout(self._remaining())
                        chunk = response.read1(min(65536, self.max_bytes + 1 - len(body)))
                        self._remaining()
                        if not chunk:
                            if response.length not in (None, 0):
                                raise TransportError('incomplete response')
                            break
                        scan = carry + chunk.lower()
                        if any(signal in scan for signal in signatures):
                            self.blocked = True
                            return Response(response.status, (), b'', '', True)
                        carry = scan[-(max(map(len, signatures)) - 1):]
                        body.extend(chunk)
                        if len(body) > self.max_bytes:
                            raise TransportError('response too large')
                    status = response.status
                    location = response.getheader('Location')
                    # Never return cookie values or authentication challenges.
                    safe_headers = tuple((k, v) for k, v in raw_headers if k.lower() not in ('set-cookie', 'www-authenticate', 'proxy-authenticate', 'authorization', 'cookie', 'location'))
                    signals = b' '.join([bytes(body[:8192]).lower()] + [v.lower().encode('latin1', 'ignore') for k, v in raw_headers if k.lower() in ('server', 'x-sucuri-block', 'cf-mitigated')])
                    blocked = status in (401, 403, 429) or any(x in signals for x in (b'captcha', b'cloudflare challenge', b'cf-mitigated', b'access denied', b'blocked by waf', b'challenge-platform')) or any(k.lower() in ('cf-mitigated', 'x-sucuri-block') for k, v in raw_headers)
                    if blocked:
                        self.blocked = True
                    locations = [v for k, v in raw_headers if k.lower() == 'location']
                    witness_match = bool(probe and probe[1] == 'witness' and status in (301, 302, 303, 307, 308) and locations == [probe[2] if len(probe) > 2 else 'https://example.invalid/'])
                    reflected = bool(probe and probe[1] == 'reflection' and b'FORTRESSINERT2026' in body)
                    if probe and probe[1] == 'cors' and status in (301, 302, 303, 307, 308):
                        self.blocked = True
                        return Response(status, (), b'', '', False, indeterminate=True)
                    if probe and status in (301, 302, 303, 307, 308) and not witness_match and probe[1] != 'baseline':
                        self.blocked = True
                        blocked = True
                    baseline_data = bytes(body) + b'\n' + b'\n'.join(v.encode('latin1', 'ignore') for k, v in raw_headers if k.lower() == 'location') if probe and probe[1] == 'baseline' else b''
                    result = Response(status, safe_headers, bytes(body), canonical, blocked, _cookie_facts(raw_headers), reflected, witness_match,
                                      baseline_marker=b'FORTRESSINERT2026' in baseline_data,
                                      baseline_first=b'https://example.invalid/' in baseline_data,
                                      baseline_second=b'https://second.invalid/' in baseline_data,
                                      headers_complete=not response.msg.defects)
                finally:
                    sock.close()
            except TransportError:
                self.blocked = True
                raise
            except (OSError, ValueError, http.client.HTTPException, ssl.SSLError):
                self.blocked = True
                network_failure = True
            if network_failure:
                raise TransportError('network request failed')
            if probe is not None or blocked or status not in (301, 302, 303, 307, 308) or not location:
                return result
            # urljoin is used only before fully revalidating the exact allowlist.
            current = urljoin(current, location)
        raise TransportError('redirect limit')
