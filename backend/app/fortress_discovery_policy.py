"""Unwired, sequential discovery policy; no DNS or network implementation.

The injected exchange must perform exactly one GET, never follow redirects, obey
its decoded-byte and timeout arguments while streaming, and return only bounded
metadata. This contract is NOT implemented by fortress_discovery_transport.get:
that function does not expose links or Location or an adjustable byte cap.
Budgets and deadlines here are cooperative; a blocking exchange cannot be killed.
GET can have effects even on an explicitly allowed route; this is not consent.
Results deliberately omit URLs, headers, bodies, link values and exceptions.
"""
from collections import deque
from dataclasses import dataclass
import math
import re
import time
from urllib.parse import urljoin, urlsplit

_PATH = re.compile(r'/[A-Za-z0-9._~/-]*\Z')
_HOST = re.compile(r'(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')
_DANGER = re.compile(r'(?:^|[/_.-])(?:logout|logoff|signout|sign[-_.]out|delete|remove|destroy|reset|admin|checkout|purchase|unsubscribe|password|close|disable|deactivate|terminate|cancel|revoke|transfer|payment|api)(?:$|[/_.-])', re.I)
_REDIRECT = frozenset((301, 302, 303, 307, 308))
# Heuristic only: unknown names and GET side effects cannot be identified reliably.
# Encoded paths, queries, fragments and non-ASCII are rejected earlier in _route.
_DYNAMIC_DANGER = re.compile(r'(?:^|[/_.~\-])(?:login|logon|signin|sign[-_.~]in|signup|sign[-_.~]up|register|auth|oauth|account|session|upload|download|subscribe|submit|edit|update|create|add|new|send|confirm|verify|search|users?|profiles?|accounts?|private|secure|billing|sessions?|settings?|carts?|shop|shopping|commandes?|comptes?|orders?|panier|paniers|paiement|paiements|factures?|customers?|clients?|addresses|address|messages?|invoices?|payments?|wallets?|reservations?|bookings?|abonnements?|preferences|dashboard|portal)(?:$|[/_.~\-])', re.I)


@dataclass(frozen=True)
class Limits:
    pages: int = 20
    requests: int = 30
    depth: int = 2
    interval: float = 0.7
    page_bytes: int = 512 * 1024
    total_bytes: int = 10 * 1024 * 1024
    seconds: float = 120

    def __post_init__(self):
        for value, lower, upper in ((self.pages, 1, 20), (self.requests, 1, 30),
                                     (self.depth, 0, 2), (self.page_bytes, 1, 512 * 1024),
                                     (self.total_bytes, 1, 10 * 1024 * 1024)):
            if type(value) is not int or not lower <= value <= upper:
                raise ValueError('invalid limits')
        for value, lower, upper in ((self.interval, 0.7, 120), (self.seconds, 0, 120)):
            if type(value) not in (int, float) or not math.isfinite(value) or not lower <= value <= upper:
                raise ValueError('invalid limits')
        if self.seconds == 0:
            raise ValueError('invalid limits')


def dynamic_limits(values):
    keys = {'pages', 'requests', 'depth', 'interval', 'page_bytes', 'total_bytes', 'seconds'}
    if type(values) is not dict or set(values) != keys:
        raise ValueError('invalid dynamic limits')
    for key, lower, upper in (('pages', 1, 5), ('requests', 1, 10), ('depth', 0, 1),
                              ('page_bytes', 1, 524288), ('total_bytes', 1, 3145728)):
        if type(values[key]) is not int or not lower <= values[key] <= upper:
            raise ValueError('invalid dynamic limits')
    for key, lower, upper in (('interval', 1, 120), ('seconds', 0, 120)):
        value = values[key]
        if type(value) not in (int, float) or not math.isfinite(value) or not lower <= value <= upper:
            raise ValueError('invalid dynamic limits')
    if values['seconds'] == 0:
        raise ValueError('invalid dynamic limits')
    return Limits(**values)


def _origin(value):
    try:
        if not isinstance(value, str) or not value.isascii() or len(value) > 2048 or re.search(r'[\x00-\x20\x7f\\%?#]', value):
            return None
        p = urlsplit(value)
        host = p.hostname
        if (p.scheme.lower() != 'https' or not host or not _HOST.fullmatch(host)
                or p.username is not None or p.password is not None or p.path not in ('', '/')
                or p.netloc.endswith(':') or p.port == 0):
            return None
        port = p.port or 443
        return 'https://' + host + (':' + str(port) if port != 443 else '')
    except ValueError:
        return None


def _path(value):
    if (not _PATH.fullmatch(value) or '//' in value
            or any(segment in ('.', '..') for segment in value.split('/'))
            or _DANGER.search(value)):
        return None
    return value


def _route(value, base, origin, allowed):
    try:
        if (not isinstance(value, str) or not value or not value.isascii() or len(value) > 2048
                or re.search(r'[\x00-\x20\x7f\\%?#]', value)):
            return None
        raw = urlsplit(value)
        # Reject dot segments before urljoin can erase them.
        if any(p in ('.', '..') for p in raw.path.split('/')) or '//' in raw.path:
            return None
        target = urlsplit(urljoin(origin + base, value))
        target_origin = _origin(target.scheme + '://' + target.netloc)
        path = _path(target.path or '/')
        if path is None or target_origin != origin:
            return None
        if allowed is None:
            last = path.rstrip('/').rsplit('/', 1)[-1]
            if (_DYNAMIC_DANGER.search(path) or _DANGER.search(path.replace('~', '/'))
                    or ('.' in last and not last.lower().endswith(('.html', '.htm')))):
                return None
            return path
        return path if path in allowed else None
    except ValueError:
        return None


def discover(origin, routes, start, exchange, *, limits=None, clock=time.monotonic, sleep=time.sleep, _record=None, dynamic=False):
    """Traverse only exact routes. exchange(url, max_bytes, timeout) is injected.

    Its response schema is {status, decoded_bytes, links, location}; links are
    already extracted navigation links, not forms. No parser or transport is wired.
    Per-call max_bytes is min(page limit, remaining total) and the exchange must
    enforce it during receipt, not merely report its size afterward.
    """
    limits = limits if limits is not None else Limits()
    if not isinstance(limits, Limits):
        raise ValueError('invalid limits')
    result = {'pages': 0, 'requests': 0, 'bytes': 0, 'complete': False, 'reason': 'scope_blocked'}
    canonical = _origin(origin)
    if canonical is None or not isinstance(routes, (list, tuple, frozenset, set)) or not routes or len(routes) > 1000:
        return result
    allowed = set()
    for route in routes:
        if not isinstance(route, str) or not route.isascii() or len(route) > 2048 or _path(route) is None:
            return result
        allowed.add(route)
    initial = _route(start, '/', canonical, allowed)
    if initial is None:
        return result
    if type(dynamic) is not bool:
        return result
    if dynamic:
        try:
            dynamic_limits(vars(limits))
        except ValueError:
            return result
        if routes != ['/'] or initial != '/':
            return result
        allowed = None
    frontier = deque([(initial, 0, frozenset())])
    seen = set()
    deadline = clock() + limits.seconds
    next_request = None
    partial = None
    scope_blocked = False
    depth_blocked = set()
    while frontier:
        path, depth, chain = frontier.popleft()
        if path in seen:
            continue
        if result['pages'] >= limits.pages:
            result['reason'] = 'page_limit'
            return result
        if result['requests'] >= limits.requests:
            result['reason'] = 'request_limit'
            return result
        remaining = limits.total_bytes - result['bytes']
        if remaining <= 0:
            result['reason'] = 'byte_limit'
            return result
        now = clock()
        if now >= deadline:
            result['reason'] = 'duration_limit'
            return result
        while next_request is not None and next_request > now:
            delay = next_request - now
            if delay >= deadline - now:
                result['reason'] = 'duration_limit'
                return result
            sleep(delay)
            now = clock()
        if now >= deadline:
            result['reason'] = 'duration_limit'
            return result
        seen.add(path)
        result['requests'] += 1
        cap = min(limits.page_bytes, remaining)
        try:
            response = exchange(canonical + path, cap, deadline - now)
        except Exception:
            result['reason'] = 'transport_error'
            return result
        next_request = clock() + limits.interval
        expired = clock() >= deadline
        if (type(response) is dict and set(response) in ({'status', 'incomplete'}, {'status', 'incomplete', 'partial_headers'})
                and response['incomplete'] is True and type(response['status']) is int
                and 200 <= response['status'] <= 599 and _record is not None):
            try:
                _record(path, depth, response['status'], [], None, canonical, allowed)
            except Exception:
                pass
            result['reason'] = 'duration_limit' if expired else 'incomplete'
            return result
        if expired:
            result['reason'] = 'duration_limit'
            return result
        if not isinstance(response, dict) or set(response) != {'status', 'decoded_bytes', 'links', 'location'}:
            result['reason'] = 'incomplete'
            return result
        status, size, links, location = (response[k] for k in ('status', 'decoded_bytes', 'links', 'location'))
        if type(size) is not int or size < 0 or size > cap:
            result['reason'] = 'byte_limit' if type(size) is int and size > cap else 'incomplete'
            return result
        result['bytes'] += size
        if type(status) is not int or not 200 <= status <= 599 or not isinstance(links, (list, tuple)) or len(links) > 1000:
            result['reason'] = 'incomplete'
            return result
        if _record is not None:
            try:
                _record(path, depth, status, links, location, canonical, allowed)
            except Exception:
                result['reason'] = 'incomplete'
                return result
        if status in _REDIRECT:
            destination = _route(location, path, canonical, allowed)
            if destination is None:
                result['reason'] = 'redirect_blocked'
                return result
            new_chain = chain | {path}
            if destination in new_chain:
                result['reason'] = 'redirect_loop'
                return result
            if destination not in seen:
                frontier.appendleft((destination, depth, new_chain))
        elif status == 204:
            # A successful response without content has no links to traverse.
            result['pages'] += 1
        elif status == 200:
            result['pages'] += 1
            for link in links:
                destination = _route(link, path, canonical, allowed)
                if destination is None:
                    scope_blocked = True
                    partial = partial or 'scope_blocked'
                elif destination not in seen:
                    if depth >= limits.depth:
                        depth_blocked.add(destination)
                        partial = partial or 'depth_limit'
                    else:
                        frontier.append((destination, depth + 1, frozenset()))
        elif 200 <= status < 300 or status == 304:
            result['reason'] = 'unknown'
            return result
        else:
            result['reason'] = 'http_refused'
            return result
    if partial == 'depth_limit' and not depth_blocked - seen:
        partial = 'scope_blocked' if scope_blocked else None
    result['complete'] = partial is None
    result['reason'] = partial or 'none'
    return result


def _safe_display_path(path):
    """Reveal only route depth, bounded for display; never segment contents."""
    if path == '/':
        return '/'
    parts = path[1:].split('/')
    projection = '/{segment}' * len(parts)
    return projection if len(parts) <= 20 and len(projection) <= 128 else '/{segment}'


def _excluded_reason(ref, base, origin):
    # Classification only; never changes eligibility or performs resolution.
    if ref is None:
        return 'unknown'
    if not isinstance(ref, str) or not ref or len(ref) > 2048 or not ref.isascii():
        return 'invalid'
    if '?' in ref or '#' in ref:
        return 'query_fragment'
    try:
        raw = urlsplit(ref)
        target = urlsplit(urljoin(origin + base, ref))
        other = _origin(target.scheme + '://' + target.netloc)
        if raw.netloc and other is not None and other != origin:
            return 'external'
        if other != origin or not target.path.startswith('/'):
            return 'invalid'
        path = target.path
        if _DANGER.search(path) or _DYNAMIC_DANGER.search(path):
            return 'sensitive'
        last = path.rstrip('/').rsplit('/', 1)[-1]
        if '.' in last and not last.lower().endswith(('.html', '.htm')):
            return 'non_html_resource'
        return 'out_of_scope' if _path(path) is not None else 'invalid'
    except ValueError:
        return 'invalid'


def discover_observed(origin, routes, start, exchange, *, limits=None, clock=time.monotonic, sleep=time.sleep, _live_paths=False, dynamic=False, private_view=False):
    """Project an injected exchange; this is not live provenance or authorization."""
    from datetime import datetime, timezone
    from . import fortress_advanced_core as core
    from .fortress_discovery_contract import valid_partial_headers
    pages, edges, pending, resource_counts = [], [], {}, []
    excluded = [0]
    depth_candidates = []
    reachable = set()
    max_depth = (limits if isinstance(limits, Limits) else Limits()).depth
    reasons = dict.fromkeys(('external', 'query_fragment', 'sensitive', 'non_html_resource',
                            'invalid', 'out_of_scope', 'depth', 'unknown'), 0)

    def get(url, cap, timeout):
        answer = exchange(url, cap, timeout)
        if (type(answer) is dict and set(answer) in ({'status', 'incomplete'}, {'status', 'incomplete', 'partial_headers'})
                and answer['incomplete'] is True and type(answer['status']) is int
                and 200 <= answer['status'] <= 599
                and ('partial_headers' not in answer or valid_partial_headers(answer['partial_headers']))):
            pending.clear()
            pending.update(observations=None, resources=None, incomplete=True)
            if 'partial_headers' in answer:
                pending['partial_headers'] = answer['partial_headers']
            return answer
        fields = {'status', 'decoded_bytes', 'links', 'location', 'observations'}
        if type(answer) is not dict or set(answer) not in (fields, fields | {'resources'}):
            return {}
        pending.clear()
        pending['observations'] = answer['observations']
        pending['resources'] = answer.get('resources')
        return {key: answer[key] for key in ('status', 'decoded_bytes', 'links', 'location')}

    def record(path, depth, status, links, location, canonical, allowed):
        observations = pending.pop('observations')
        resources = pending.pop('resources')
        if resources is not None:
            if (status != 200 or type(resources) is not dict
                    or set(resources) != {'script', 'stylesheet'}
                    or any(type(v) is not int or not 0 <= v <= 1000 for v in resources.values())):
                raise ValueError('invalid resources')

        incomplete = pending.pop('incomplete', False)
        partial_headers = pending.pop('partial_headers', None)
        state = 'incomplete' if incomplete or status == 304 else 'access_denied' if status == 403 else 'redirected' if 300 <= status < 400 else 'http_error' if status >= 400 else 'complete' if status in (200, 204) else 'incomplete'
        findings = []
        if state == 'complete':
            if type(observations) is not dict or set(observations) != set(core.empty()) or observations['http_status'] != status:
                raise ValueError('invalid observations')
            findings = core.findings(observations)
            if not core._validate_completed(observations, findings):
                raise ValueError('invalid observations')
        elif observations is not None:
            raise ValueError('invalid observations')
        if resources is not None:
            resource_counts.extend((path, kind, resources[kind]) for kind in ('script', 'stylesheet') if resources[kind])
        pages.append((path, depth, status, state, datetime.now(timezone.utc).isoformat(), observations, findings, partial_headers))
        reachable.add(path)
        refs = [] if incomplete else [(location, 'redirect')] if status in _REDIRECT else [(link, 'link') for link in links] if status == 200 else []
        for ref, kind in refs:
            target = _route(ref, path, canonical, allowed)
            if target is None:
                excluded[0] += 1
                reasons[_excluded_reason(ref, path, canonical)] += 1
            else:
                if kind == 'link' and depth >= max_depth:
                    depth_candidates.append(target)
                else:
                    reachable.add(target)
                if (path, target, kind) not in edges:
                    edges.append((path, target, kind))

    outcome = discover(origin, routes, start, get, limits=limits, clock=clock, sleep=sleep, _record=record, dynamic=dynamic)
    # Count references, not unique destinations; a shorter scheduled route (or
    # a redirect at admissible depth) means depth did not exclude that target.
    reasons['depth'] = sum(target not in reachable for target in depth_candidates)
    excluded[0] += reasons['depth']
    aliases = {page[0]: f'page-{i}' for i, page in enumerate(pages, 1)}
    for source, target, kind in edges:
        if target not in aliases:
            aliases[target] = f'page-{len(aliases) + 1}'
    projected = []
    for path, depth, status, state, observed_at, observations, findings, partial_headers in pages:
        alias = aliases[path]
        display_route = _safe_display_path(path) if _live_paths else alias
        for finding in findings:
            finding.pop('route_id')
            finding.update(route=display_route, confidence='caller_declared', provenance='response_headers')
            if finding['limit'] == 'head_response_only':
                finding['limit'] = 'response_headers_only'
        projected.append({'id': alias, 'route': display_route, 'depth': depth, 'status': status,
                          'state': state, 'observed_at': observed_at, 'observations': observations, 'findings': findings})
        if partial_headers is not None:
            projected[-1]['partial_headers'] = partial_headers
    # The fixed lab contract has no scope_blocked reason. Preserve the partial
    # state and exclusion count rather than claiming lab completeness; the raw
    # policy reason remains distinct pending a dedicated live contract.
    reason = 'unknown' if outcome['reason'] == 'scope_blocked' else outcome['reason']
    result = {'schema': 'fortress.discovery/1', 'provenance': 'lab', 'complete': outcome['complete'],
            'reason': reason, 'requests': outcome['requests'], 'bytes': outcome['bytes'], 'exclusion_reasons': reasons,
            'pages': projected, 'relations': [{'from': aliases[a], 'to': aliases[b], 'kind': k} for a, b, k in edges],
            'resources': [{'page': aliases[path], 'kind': kind, 'count': count} for path, kind, count in resource_counts],
            'limits': ['lab_only', 'excluded_links:' + str(excluded[0]),
                 'no_external_requests', 'no_authentication', 'headers_only_analysis', 'not_a_vulnerability_or_compliance_conclusion']}
    if private_view is True:
        from .fortress_discovery_private import project
        result['private_paths'] = [{'id': alias, 'path': project(path)} for path, alias in aliases.items()]
    return result
