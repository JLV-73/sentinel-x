"""Fixed, owned loopback HTTPS fixture for the discovery lab API.

No caller-selected host, port, certificate, socket or response is accepted.
The routes below are an explicit allowlist, not a general safe-GET policy.
"""
from collections import deque
from datetime import datetime, timezone
from html.parser import HTMLParser
import socket
import ssl
import threading
import time
import hashlib
import re
from urllib.parse import urljoin, urlsplit

from .fortress_discovery_a import _DANGEROUS
from . import fortress_mvp as transport
from . import fortress_discovery_transport as discovery_transport
from . import fortress_discovery_intelligence as intelligence

_NAME = transport._NAME
_ROUTES = {
    '/': (200, b'<a href="/jump">next</a><a href="/third">third</a><a href="/delete">bad</a><a href="/find?token=SECRET_EXAMPLE">bad</a><a href="https://outside.invalid/">bad</a>'),
    '/jump': (302, b''),
    '/second': (200, b'<a href="/third">third</a>'),
    '/third': (200, b'<p>SECRET_EXAMPLE</p>'),
}


def _route(value, current):
    try:
        if not isinstance(value, str) or not value or len(value) > 2048 or not value.isascii():
            return None
        if re.search(r'[\x00-\x20\x7f\\%]', value) or '?' in value:
            return None
        raw = urlsplit(value)
        if raw.username is not None or raw.password is not None:
            return None
        target = urlsplit(urljoin('https://standard-lab.invalid' + current, value))
        if (target.scheme != 'https' or target.hostname != 'standard-lab.invalid'
                or (target.port or 443) != 443):
            return None
        path = target.path or '/'
        if not intelligence._ROUTE.fullmatch(path) or path.startswith('//'):
            return None
        if _DANGEROUS.search(path) or re.search(r'(?:^|/)api(?:/|$)', path, re.I):
            return None
        return path
    except ValueError:
        return None


def _id(path):
    return 'route-' + hashlib.sha256(path.encode('ascii')).hexdigest()


class _Links(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self.resources = [], []

    def handle_starttag(self, tag, attrs):
        values, duplicates = {}, set()
        for key, value in attrs:
            if key in values:
                duplicates.add(key)
            values[key] = value
        if tag == 'a' and 'href' in values and 'href' not in duplicates:
            self.links.append(values['href'])
        elif tag == 'script' and 'src' in values:
            self.resources.append('script')
        elif tag == 'link' and 'stylesheet' in (values.get('rel') or '').lower().split():
            self.resources.append('stylesheet')
        elif tag == 'form':
            self.resources.append('form')
        for attr in ('href', 'src', 'action'):
            value = values.get(attr)
            if isinstance(value, str) and re.search(r'(?:^|/)api(?:/|\?|#|$)', value, re.I):
                self.resources.append('api')


def _one_exchange(path):
    """Connect only to our own listener and use the v0.2.3 TLS/GET engine."""
    if _route(path, '/') != path:
        raise ValueError('fixture route not allowed')
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client = server = None
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
            raise OSError('peer mismatch')
        listener.close()
        server.settimeout(3)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(transport._CERTS / 'server.pem'), str(transport._CERTS / 'server-key.pem'))
        def serve():
            try:
                with context.wrap_socket(server, server_side=True) as tls:
                    data = b''
                    while b'\r\n\r\n' not in data and len(data) < 4096:
                        chunk = tls.recv(4096 - len(data))
                        if not chunk:
                            return
                        data += chunk
                    if not data.startswith(('GET ' + path + ' HTTP/1.1\r\n').encode('ascii')):
                        return
                    entry = _ROUTES.get(path, (404, b''))
                    status, body = entry[:2]
                    destination = entry[2] if len(entry) > 2 else '/second'
                    extra = entry[3] if len(entry) > 3 else []
                    extra_headers = b''.join((name + ': ' + value + '\r\n').encode('ascii') for name, value in extra)
                    location = b'Location: ' + destination.encode('ascii') + b'\r\n' if status in (301, 302, 303, 307, 308) else b''
                    response = (b'HTTP/1.1 ' + str(status).encode('ascii') + b' Fixture'
                                + b'\r\nContent-Type: text/html; charset=utf-8\r\n' + location + extra_headers
                                + b'Content-Length: ' + str(len(body)).encode('ascii')
                                + b'\r\nConnection: close\r\n\r\n' + body)
                    tls.sendall(response)
                    tls.unwrap().close()
            except (OSError, ssl.SSLError):
                pass
        thread = threading.Thread(target=serve)
        thread.start()
        verify = ssl.create_default_context(cafile=str(transport._CERTS / 'ca.pem'))
        deadline = time.monotonic() + 3
        with verify.wrap_socket(client, server_hostname=_NAME, suppress_ragged_eofs=False) as tls:
            client = None
            tls.sendall(('GET ' + path + ' HTTP/1.1\r\nHost: ' + _NAME + '\r\nConnection: close\r\n\r\n').encode('ascii'))
            status, size, fields, body = discovery_transport._read_response(tls, deadline, project='lab_response')
        headers = b''.join(name + b': ' + value + b'\r\n' for name, value in fields)
        return status, b'HTTP/1.1 ' + str(status).encode('ascii') + b' Fixture\r\n' + headers + b'\r\n' + body
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
            thread.join(timeout=4)


def run_lab(*, request_limit=30):
    """Run only the embedded fixture, then project each observed response."""
    if type(request_limit) is not int or not 1 <= request_limit <= 30:
        raise ValueError('invalid request limit')
    result = {'pages': 0, 'requests': 0, 'bytes': 0, 'excluded_links': 0, 'complete': False, 'reason': 'unknown',
              'graph': {'pages': [], 'relations': [], 'resources': []}}
    collected = []
    _crawl(result, collected, request_limit)
    result['intelligence'] = intelligence.analyze_pages(collected)
    for page, source in zip(result['intelligence']['pages'], collected):
        page['graph_route'] = _id(source['route'])
    return result


def _crawl(result, collected, request_limit):
    graph = result['graph']
    relation_keys = set()
    depth_candidates = set()
    frontier, seen = deque([('/', 0, frozenset())]), set()
    deadline = time.monotonic() + 120
    next_request = time.monotonic()
    while frontier:
        path, depth, redirect_chain = frontier.popleft()
        if path in seen:
            continue
        if result['requests'] >= request_limit:
            result['reason'] = 'request_limit'
            return result
        if time.monotonic() >= deadline:
            result['reason'] = 'duration_limit'
            return result
        delay = next_request - time.monotonic()
        while delay > 0:
            time.sleep(delay)
            delay = next_request - time.monotonic()
        if time.monotonic() >= deadline:
            result['reason'] = 'duration_limit'
            return result
        seen.add(path)
        result['requests'] += 1
        try:
            status, response = _one_exchange(path)
            next_request = time.monotonic() + 0.7
            result['bytes'] += len(response.split(b'\r\n\r\n', 1)[1])
            if result['bytes'] > 10 * 1024 * 1024:
                result['reason'] = 'byte_limit'
                return result
            lines = response.split(b'\r\n\r\n', 1)[0].split(b'\r\n')[1:]
            headers = []
            for line in lines:
                name, value = line.split(b':', 1)
                headers.append((name.decode('ascii'), value.strip(b' \t').decode('ascii')))
            collected.append({'route': path, 'observed_at': datetime.now(timezone.utc).isoformat(),
                              'status': status, 'complete': True, 'headers': headers})
            graph['pages'].append({'route': _id(path), 'depth': depth, 'status': status})
            if status in (301, 302, 303, 307, 308):
                headers = response.split(b'\r\n\r\n', 1)[0].split(b'\r\n')
                locations = [line[9:].strip() for line in headers if line.lower().startswith(b'location:')]
                destination = _route(locations[0].decode('ascii'), path) if len(locations) == 1 else None
                if destination is None:
                    result['reason'] = 'redirect_blocked'
                    return result
                key = (_id(path), _id(destination), 'redirect')
                if key not in relation_keys:
                    graph['relations'].append({'from': key[0], 'to': key[1], 'kind': key[2]})
                    relation_keys.add(key)
                chain = redirect_chain | {path}
                if destination in chain:
                    result['reason'] = 'redirect_loop'
                    return result
                if destination not in seen:
                    frontier.appendleft((destination, depth, chain))
            elif status == 200:
                result['pages'] += 1
                body = response.split(b'\r\n\r\n', 1)[1]
                parser = _Links()
                parser.feed(body.decode('utf-8', errors='strict'))
                parser.close()
                graph['resources'].extend({'page': _id(path), 'kind': kind} for kind in parser.resources)
                for link in parser.links:
                    target = _route(link, path)
                    if target is None:
                        result['excluded_links'] += 1
                        continue
                    key = (_id(path), _id(target), 'link')
                    if key not in relation_keys:
                        graph['relations'].append({'from': key[0], 'to': key[1], 'kind': key[2]})
                        relation_keys.add(key)
                    if target not in seen:
                        if depth >= 2:
                            depth_candidates.add(target)
                        else:
                            frontier.append((target, depth + 1, frozenset()))
                if result['pages'] >= 20 and any(item[0] not in seen for item in frontier):
                    result['reason'] = 'page_limit'
                    return result
            else:
                result['reason'] = 'http_refused'
                return result
        except (OSError, ValueError, UnicodeError):
            result['reason'] = 'incomplete'
            return result
    depth_limited = bool(depth_candidates - seen)
    result['complete'] = not depth_limited
    result['reason'] = 'depth_limit' if depth_limited else 'none'
    return result
