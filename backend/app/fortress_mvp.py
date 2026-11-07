"""Local-only HTTPS demonstration. No public network diagnostic is enabled.

The test certificates and server key in fortress_mvp_tls are PUBLIC fixtures;
never use them for production and never install the CA in a system trust store.
"""
import datetime
import email.parser
import ipaddress
import re
import socket
import ssl
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

_CERTS = Path(__file__).with_name('fortress_mvp_tls')
_NAME = 'standard-lab.invalid'
_LIMIT = 65536
_CSP_DIRECTIVES = frozenset(('default-src', 'script-src', 'script-src-elem', 'script-src-attr',
    'style-src', 'style-src-elem', 'style-src-attr', 'img-src', 'connect-src', 'font-src',
    'frame-src', 'object-src', 'base-uri', 'form-action', 'frame-ancestors'))


def _csp_details(values):
    empty = {'status': 'indeterminate', 'directives': []}
    if not values:
        return {'status': 'missing', 'directives': []}
    if len(values) != 1 or len(values[0]) > 8192 or not values[0].isascii() or ',' in values[0]:
        return empty
    seen, result = set(), []
    for part in values[0].split(';'):
        tokens = part.strip().split()
        if not tokens:
            continue
        name = tokens[0].lower()
        if not re.fullmatch(r'[a-z][a-z0-9-]*', name) or name in seen:
            return empty
        seen.add(name)
        if any(not re.fullmatch(r"[A-Za-z0-9_./:+*'=-]+", token) for token in tokens[1:]):
            return empty
        if name in _CSP_DIRECTIVES:
            sources = [token.lower() for token in tokens[1:]]
            wildcard = 'any' if '*' in sources else 'domain' if any(re.fullmatch(r'(?:[a-z][a-z0-9+.-]*://)?\*\.[a-z0-9.-]+(?::[0-9]+)?(?:/[^ ]*)?', s) for s in sources) else 'none'
            result.append({'directive': name, 'inline': "'unsafe-inline'" in sources, 'wildcard': wildcard})
    return {'status': 'present', 'directives': result} if seen else empty


def _empty():
    return {'mode': 'fixture', 'target': None, 'route': '[redacted route]',
            'generated_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'http_status': None, 'failure_code': 'unknown',
            'tls': {'certificate': 'indeterminate', 'hostname': 'indeterminate',
                    'protocol': None, 'not_before': None, 'not_after': None},
            'headers': {key: 'indeterminate' for key in ('hsts', 'csp', 'x_content_type_options', 'referrer_policy', 'permissions_policy')},
            'security_details': {'hsts': {'status': 'indeterminate', 'seconds': None},
                'csp': {'status': 'indeterminate', 'directives': []}, 'csp_report_only': {'status': 'indeterminate', 'directives': []}},
            'cookies': {'count': None, 'secure': None, 'httponly': None, 'samesite': None},
            'findings': [], 'limits': ['fixture_only', 'no_redirect_following', 'no_active_tests', 'no_internet_qualification']}


def diagnose(url, *, authorized=False):
    """Internal only, not an API. Caller authorization is not security qualification.

    DNS is synchronous and concurrency/termination remain unqualified; do not
    expose this callable to untrusted input or enable cockpit Internet access.
    """
    out = _empty()
    out['mode'] = 'disabled'
    out['failure_code'] = 'not_performed'
    out['findings'] = [{'id': 'internet_diagnostic', 'state': 'not_performed', 'evidence': 'disabled'}]
    if authorized is not True:
        return out
    out['mode'] = 'internal'
    out['limits'] = ['internal_unqualified', 'no_redirect_following', 'no_active_tests', 'no_internet_qualification']
    out['findings'] = []
    client = None
    try:
        if not isinstance(url, str) or len(url) > 2048 or not url.isascii() or re.search(r'[\x00-\x20\x7f\\]', url) or '#' in url:
            raise ValueError('invalid URL')
        parsed = urlsplit(url)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.port not in (None, 443):
            raise ValueError('invalid URL')
        host = parsed.hostname
        if len(host) > 253 or not re.fullmatch(r'[A-Za-z0-9.-]+', host) or not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label) for label in host.split('.')):
            raise ValueError('invalid hostname')
        target = parsed.path or '/'
        if not target.startswith('/') or re.search(r'%(?![0-9a-fA-F]{2})', target + parsed.query):
            raise ValueError('invalid target')
        out['target'] = 'https://' + host + ('/' if target == '/' else '/[redacted path]')
        out['route'] = '/' if target == '/' else '[redacted route]'
        if parsed.query:
            target += '?' + parsed.query
        client = _public_socket(host, time.monotonic() + 5)
        context = ssl.create_default_context()
        _https_exchange(client, host, context, out, target)
        client = None
    except (ValueError, OSError, ssl.SSLError):
        out['failure_code'] = 'tls_or_transport'
    finally:
        if client is not None:
            client.close()
    return out


def _parse_response(data, out):
    # Only accept a conservative HTTP/1.1 message with a known complete body.
    marker = data.find(b'\r\n\r\n')
    if marker < 0 or b'\n' in data[:marker].replace(b'\r\n', b''):
        return False
    lines = data[:marker].split(b'\r\n')
    if not re.fullmatch(rb'HTTP/1\.1 [2-5][0-9]{2} [\x20-\x7e]*', lines[0]):
        return False
    code = lines[0][9:12]
    if any(not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+:[\x09\x20-\x7e\x80-\xff]*", line) for line in lines[1:]):
        return False
    headers = email.parser.BytesParser().parsebytes(b'\r\n'.join(lines[1:]) + b'\r\n\r\n')
    lengths = headers.get_all('Content-Length', [])
    if headers.get_all('Transfer-Encoding', []) or len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit():
        return False
    length = int(lengths[0])
    if length > _LIMIT or len(data[marker + 4:]) != length:
        return False
    status = int(code)
    if status in (204, 304):
        return False
    out['http_status'] = status
    if 300 <= status < 400:
        out['failure_code'] = 'redirected'
        return True
    out['failure_code'] = 'none' if 200 <= status < 300 else 'http_refused'
    names = {'hsts': 'Strict-Transport-Security', 'csp': 'Content-Security-Policy',
             'x_content_type_options': 'X-Content-Type-Options', 'referrer_policy': 'Referrer-Policy',
             'permissions_policy': 'Permissions-Policy'}
    for key, name in names.items():
        out['headers'][key] = 'present' if headers.get_all(name, []) else 'absent'
    hsts = headers.get_all('Strict-Transport-Security', [])
    out['security_details']['hsts'] = {'status': 'missing', 'seconds': None} if not hsts else {'status': 'indeterminate', 'seconds': None}
    if hsts:
        parts = [p.strip() for p in hsts[0].split(';')]
        directives = [p.partition('=') for p in parts if p]
        maxages = [v.strip() for n, sep, v in directives if n.strip().lower() == 'max-age' and sep]
        names_seen = [n.strip().lower() for n, _, _ in directives]
        if (len(hsts) != 1 or len(maxages) != 1 or not re.fullmatch(r'[0-9]{1,12}', maxages[0])
                or names_seen.count('max-age') != 1 or len(names_seen) != len(set(names_seen))
                or any(not re.fullmatch(r'[A-Za-z][A-Za-z0-9-]*', n) for n in names_seen)
                or any(sep for n, sep, _ in directives if n.strip().lower() in ('includesubdomains', 'preload'))):
            out['headers']['hsts'] = 'indeterminate'
        elif any(sep and not re.fullmatch(r'[A-Za-z0-9._-]+', v.strip()) for _, sep, v in directives):
            out['headers']['hsts'] = 'indeterminate'
        else:
            seconds = int(maxages[0])
            out['security_details']['hsts'] = {'status': 'disabled' if seconds == 0 else 'positive', 'seconds': seconds}
    out['security_details']['csp'] = _csp_details(headers.get_all('Content-Security-Policy', []))
    out['security_details']['csp_report_only'] = _csp_details(headers.get_all('Content-Security-Policy-Report-Only', []))
    cookies = headers.get_all('Set-Cookie', [])
    attributes = []
    valid = True
    for cookie in cookies:
        items = cookie.split(';')
        name, sep, value = items[0].strip().partition('=')
        if not sep or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) or not re.fullmatch(r'[\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]*', value):
            valid = False
        parsed_attrs = [item.strip().lower().partition('=') for item in items[1:]]
        for attr in ('secure', 'httponly', 'samesite'):
            matches = [(s, v.strip()) for n, s, v in parsed_attrs if n.strip() == attr]
            if len(matches) > 1 or (matches and ((attr != 'samesite' and matches[0][0]) or (attr == 'samesite' and (not matches[0][0] or matches[0][1] not in ('strict', 'lax', 'none'))))):
                valid = False
        attributes.append({n.strip() for n, _, _ in parsed_attrs})
    out['cookies'] = {'count': len(cookies), **{key: sum(key in a for a in attributes) if valid and cookies else None for key in ('secure', 'httponly', 'samesite')}}
    out['findings'] = [{'id': 'http_response', 'state': 'observed' if status < 300 else 'attention',
                        'evidence': 'http_success' if status < 300 else 'http_refused'},
                       {'id': 'tls_handshake', 'state': 'observed', 'evidence': 'fixture_tls_verified' if out['mode'] == 'fixture' else 'tls_verified'}]
    return True


def _public_ip(value):
    # Derived from the Bubble probe: reject mixed/private/scoped answers.
    if '%' in value:
        raise ValueError('scoped address')
    ip = ipaddress.ip_address(value)
    if (not ip.is_global or ip.is_multicast or ip.is_loopback or ip.is_reserved
            or ip.is_link_local or ip.is_unspecified or getattr(ip, 'ipv4_mapped', None)):
        raise ValueError('nonpublic address')
    return ip


def _public_socket(host, deadline):
    """Unexposed building block; DNS is synchronous and not wall-clock bounded."""
    rows = socket.getaddrinfo(host, 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
    if not rows:
        raise ValueError('empty DNS')
    addresses = []
    for family, kind, _proto, _canon, address in rows:
        if family not in (socket.AF_INET, socket.AF_INET6) or kind != socket.SOCK_STREAM:
            raise ValueError('unexpected DNS record')
        ip = _public_ip(address[0])
        if family == socket.AF_INET6 and len(address) > 3 and address[3] != 0:
            raise ValueError('scoped address')
        addresses.append(ip)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError('DNS exceeded deadline')
    selected = addresses[0]
    sock = socket.socket(socket.AF_INET6 if selected.version == 6 else socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(min(5, remaining))
        sock.connect((str(selected), 443))
        if _public_ip(sock.getpeername()[0]) != selected:
            raise ValueError('peer mismatch')
        return sock
    except BaseException:
        sock.close()
        raise


def _https_exchange(client, hostname, context, out, target='/'):
    """Single TLS/GET/parse engine; connected socket is supplied by trusted code only."""
    if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
        raise ValueError('unsafe TLS context')
    deadline = time.monotonic() + 3
    client.settimeout(3)
    with context.wrap_socket(client, server_hostname=hostname) as tls:
        cert = tls.getpeercert()
        out['tls'] = {'certificate': 'verified', 'hostname': 'verified', 'protocol': tls.version(),
                      'not_before': cert.get('notBefore'), 'not_after': cert.get('notAfter')}
        tls.sendall(('GET ' + target + ' HTTP/1.1\r\nHost: ' + hostname + '\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n').encode('ascii'))
        data = b''
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('deadline')
            tls.settimeout(min(3, remaining))
            chunk = tls.recv(min(4096, _LIMIT + 1 - len(data)))
            if not chunk:
                break
            data += chunk
            if len(data) > _LIMIT:
                raise ValueError('response limit')
        if not _parse_response(data, out):
            out['failure_code'] = 'incomplete'


def _run_fixture(scenario, response=None):
    if scenario not in ('ok', 'forbidden', 'tls-error'):
        raise ValueError('invalid fixture scenario')
    out = _empty()
    out['target'] = 'https://' + _NAME + '/'
    out['route'] = '/'
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client = None
    server = None
    thread = None
    try:
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(3)
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(3)
        client.connect(listener.getsockname())
        server, peer = listener.accept()
        if peer != client.getsockname() or client.getpeername() != server.getsockname():
            raise OSError('fixture peer mismatch')
        listener.close()
        server.settimeout(3)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(_CERTS / 'server.pem'), str(_CERTS / 'server-key.pem'))
        if response is None:
            status = b'200 OK' if scenario == 'ok' else b'403 Forbidden'
            response = (b'HTTP/1.1 ' + status + b'\r\nContent-Length: 0\r\n'
                        b'Strict-Transport-Security: max-age=31536000\r\n'
                        b'X-Content-Type-Options: nosniff\r\n'
                        b'Set-Cookie: fixture=secret; Secure; HttpOnly; SameSite=Lax\r\n'
                        b'Connection: close\r\n\r\n')

        def serve():
            try:
                with context.wrap_socket(server, server_side=True) as tls:
                    data = b''
                    deadline = time.monotonic() + 3
                    while b'\r\n\r\n' not in data and len(data) < 4096:
                        tls.settimeout(max(0.001, deadline - time.monotonic()))
                        data += tls.recv(4096 - len(data))
                        if not data or time.monotonic() >= deadline:
                            return
                    tls.sendall(response)
            except (OSError, ssl.SSLError):
                pass
        thread = threading.Thread(target=serve, daemon=False)
        thread.start()
        verify = ssl.create_default_context(cafile=str(_CERTS / 'ca.pem'))
        _https_exchange(client, ('incorrect.invalid' if scenario == 'tls-error' else _NAME), verify, out)
        client = None
    except (OSError, ssl.SSLError, ValueError):
        out['failure_code'] = 'tls_or_transport'
    finally:
        listener.close()
        if client is not None:
            client.close()
        if server is not None:
            try:
                server.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            server.close()
        if thread is not None:
            thread.join()
    return out


def run_demo(scenario):
    """Run one of three fixed, owned loopback fixtures; accepts no target."""
    result = _run_fixture(scenario)
    result['scenario'] = scenario
    return result
