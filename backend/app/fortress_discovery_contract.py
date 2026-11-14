"""Discovery API v1: opaque identifiers and lossy live display paths.

The fixed owned HTTPS lab and guarded live worker have separate provenance.
Both require Host/Origin/capability/consent checks. Live requires HTTPS and an
explicit exact route scope, and may perform network requests on that scope.
Lab completeness covers permitted fixture navigation, not excluded links;
`limits` includes their count. GET may have side effects; this is not a scan
or compliance conclusion. Workers use the existing Windows Job supervisor;
native-failure, cross-session ACL and UI cancellation limitations remain.
"""
from collections import Counter

PARTIAL_HEADER_NAMES = ('strict-transport-security', 'content-security-policy',
                        'content-security-policy-report-only', 'x-content-type-options',
                        'referrer-policy', 'permissions-policy', 'set-cookie')


def valid_partial_headers(value):
    return (type(value) is dict and set(value) == {'present', 'completeness'}
            and value['completeness'] == 'headers_validated_body_incomplete'
            and type(value['present']) is list
            and all(type(name) is str and name in PARTIAL_HEADER_NAMES for name in value['present'])
            and len(value['present']) == len(set(value['present'])))


def project_lab(result):
    graph = result['graph']
    analyzed = result['intelligence']['pages']
    mapping = {page['graph_route']: f'page-{index}' for index, page in enumerate(analyzed, 1)}
    # Include unresolved graph endpoints using opaque, invocation-local labels.
    for relation in graph['relations']:
        for key in ('from', 'to'):
            identity = relation[key]
            if identity not in mapping:
                mapping[identity] = f'page-{len(mapping) + 1}'
    depths = {entry['route']: entry['depth'] for entry in graph['pages']}
    pages = []
    for page in analyzed:
        identity = page['graph_route']
        alias = mapping[identity]
        findings = []
        for finding in page['findings']:
            finding = dict(finding)
            finding['route'] = alias
            findings.append(finding)
        pages.append({'id': alias, 'route': alias, 'depth': depths[identity],
                      'status': page['status'], 'state': page['state'],
                      'observed_at': page['observed_at'], 'findings': findings,
                      'observations': page['observations']})
    relations = [{'from': mapping[r['from']], 'to': mapping[r['to']], 'kind': r['kind']} for r in graph['relations']]
    counts = Counter((mapping[r['page']], r['kind']) for r in graph['resources'])
    resources = [{'page': p, 'kind': kind, 'count': count} for (p, kind), count in counts.items()]
    return {'schema': 'fortress.discovery/1', 'provenance': 'lab',
            'complete': result['complete'], 'reason': result['reason'],
            'requests': result['requests'], 'bytes': result['bytes'], 'pages': pages,
            'relations': relations, 'resources': resources,
            'limits': ['lab_only', 'excluded_links:' + str(result['excluded_links']),
                       'no_external_requests', 'no_authentication', 'headers_only_analysis',
                       'not_a_vulnerability_or_compliance_conclusion']}


def valid_lab(value):
    """Reject untrusted worker output, including arbitrary text nested in facts."""
    return _valid(value, 'lab')


def valid_live(value):
    return _valid(value, 'live')


def _valid_display_path(value):
    if type(value) is not str or len(value) > 128 or not value.startswith('/'):
        return False
    if value == '/':
        return True
    parts = value[1:].split('/')
    return len(parts) <= 20 and all(part == '{segment}' for part in parts)


def _valid(value, provenance):
    import re
    from datetime import datetime
    from . import fortress_advanced_core as core
    try:
        keys = {'schema', 'provenance', 'complete', 'reason', 'requests', 'bytes', 'pages', 'relations', 'resources', 'limits'}
        if (type(value) is not dict or not keys <= set(value) or set(value) - keys - {'diagnostic', 'exclusion_reasons', 'private_paths', 'graph_omitted_relations'}
                or value['schema'] != 'fortress.discovery/1' or value['provenance'] != provenance
                or type(value['complete']) is not bool or value['reason'] not in ('none', 'unknown', 'scope_blocked', 'transport_error', 'request_limit', 'page_limit', 'byte_limit', 'duration_limit', 'redirect_blocked', 'redirect_loop', 'incomplete', 'http_refused', 'depth_limit')
                or value['complete'] != (value['reason'] == 'none')
                or type(value['requests']) is not int or not 0 <= value['requests'] <= 30
                or type(value['bytes']) is not int or not 0 <= value['bytes'] <= 10 * 1024 * 1024
                or type(value['pages']) is not list or len(value['pages']) > value['requests']):
            return False
        if 'diagnostic' in value:
            diagnostic = value['diagnostic']
            if (type(diagnostic) is not dict or set(diagnostic) != {'phase', 'requests_sent', 'responses_received'}
                    or diagnostic['phase'] not in ('dns', 'scope', 'connect', 'tls', 'timeout', 'http', 'parse', 'budget', 'unknown', 'none')
                    or (diagnostic['phase'] == 'none') != value['complete']):
                return False
            expected = {'none': 'none', 'scope_blocked': 'scope', 'redirect_blocked': 'scope',
                        'redirect_loop': 'scope', 'http_refused': 'http', 'request_limit': 'budget',
                        'page_limit': 'budget', 'byte_limit': 'budget', 'depth_limit': 'budget',
                        'unknown': 'unknown'}
            if value['reason'] in expected and diagnostic['phase'] != expected[value['reason']]:
                return False
            if value['reason'] == 'duration_limit' and diagnostic['phase'] not in ('budget', 'timeout'):
                return False
            sent, received = diagnostic['requests_sent'], diagnostic['responses_received']
            if any(v is not None and (type(v) is not int or not 0 <= v <= value['requests']) for v in (sent, received)):
                return False
            if sent is not None and received is not None and received > sent:
                return False
            if received is not None and received < len(value['pages']):
                return False
            if value['complete'] and (sent is not None and sent != value['requests']
                                      or received is not None and received != value['requests']):
                return False
        if provenance == 'live' and value['requests'] == 0 and value['bytes'] != 0:
            return False
        ids = set()
        for i, page in enumerate(value['pages'], 1):
            alias = f'page-{i}'
            page_keys = {'id', 'route', 'depth', 'status', 'state', 'observed_at', 'findings', 'observations'}
            if (type(page) is not dict or not page_keys <= set(page) or set(page) - page_keys - {'partial_headers', 'tls'}
                    or page['id'] != alias
                    or not (page['route'] == alias or (provenance == 'live' and _valid_display_path(page['route'])))
                    or type(page['depth']) is not int or not 0 <= page['depth'] <= 2
                    or type(page['status']) is not int or not 200 <= page['status'] <= 599
                    or type(page['observed_at']) is not str or len(page['observed_at']) > 40):
                return False
            if 'tls' in page:
                tls = page['tls']
                if (type(tls) is not dict or set(tls) != {'version', 'certificate_verified', 'hostname_verified', 'not_after'}
                        or tls['version'] not in ('TLSv1.2', 'TLSv1.3', 'unknown')
                        or tls['certificate_verified'] is not True or tls['hostname_verified'] is not True):
                    return False
                if tls['not_after'] is not None:
                    if type(tls['not_after']) is not str or re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', tls['not_after']) is None:
                        return False
                    datetime.strptime(tls['not_after'], '%Y-%m-%dT%H:%M:%SZ')
            stamp = datetime.fromisoformat(page['observed_at'])
            if stamp.utcoffset() is None:
                return False
            ids.add(alias)
            status = page['status']
            state = 'incomplete' if status == 304 else 'access_denied' if status == 403 else 'redirected' if 300 <= status < 400 else 'http_error' if status >= 400 else 'complete' if status in (200, 204) else 'incomplete'
            if page['state'] == 'incomplete':
                state = 'incomplete'
            if page['state'] != state:
                return False
            if 'partial_headers' in page and (state != 'incomplete' or not valid_partial_headers(page['partial_headers'])):
                return False
            if state == 'incomplete' and (value['complete'] or value['reason'] not in ('unknown', 'incomplete', 'duration_limit')):
                return False
            if state != 'complete':
                if page['observations'] is not None or page['findings'] != []:
                    return False
            else:
                obs = page['observations']
                if type(obs) is not dict or set(obs) != set(core.empty()) or obs['http_status'] != status:
                    return False
                expected = core.findings(obs)
                if not core._validate_completed(obs, expected):
                    return False
                for item in expected:
                    item.pop('route_id')
                    item.update(route=page['route'], confidence='caller_declared', provenance='response_headers')
                    if item['limit'] == 'head_response_only':
                        item['limit'] = 'response_headers_only'
                if page['findings'] != expected:
                    return False
        if provenance == 'live' and value['complete']:
            if (not value['pages'] or len(value['pages']) != value['requests']
                    or not any(page['status'] in (200, 204) for page in value['pages'])
                    or any(page['status'] not in (200, 204, 301, 302, 303, 307, 308) for page in value['pages'])):
                return False
        if 'graph_omitted_relations' in value and (type(value['graph_omitted_relations']) is not int or not 1 <= value['graph_omitted_relations'] <= 30000 or value['graph_omitted_relations'] + len(value['relations']) > 30000):
            return False
        if type(value['relations']) is not list or len(value['relations']) > 1000:
            return False
        seen_relations, unresolved = set(), set()
        statuses = {page['id']: page['status'] for page in value['pages']}
        incomplete_ids = {page['id'] for page in value['pages'] if page['state'] == 'incomplete'}
        for r in value['relations']:
            if (type(r) is not dict or set(r) != {'from', 'to', 'kind'} or r['from'] not in ids
                    or not isinstance(r['to'], str) or not re.fullmatch(r'page-[1-9][0-9]{0,2}', r['to'])
                    or r['kind'] not in ('link', 'redirect')
                    or (provenance == 'live' and value['complete'] and r['to'] not in ids)):
                return False
            edge = (r['from'], r['to'], r['kind'])
            if edge in seen_relations or r['from'] in incomplete_ids or (r['kind'] == 'redirect' and not 300 <= statuses[r['from']] < 400):
                return False
            seen_relations.add(edge)
            if r['to'] not in ids:
                unresolved.add(int(r['to'][5:]))
        if unresolved and unresolved != set(range(len(ids) + 1, len(ids) + len(unresolved) + 1)):
            return False
        if 'private_paths' in value:
            from .fortress_discovery_private import valid_path
            paths = value['private_paths']
            expected_ids = ids | {f'page-{n}' for n in unresolved}
            if (provenance != 'live' or type(paths) is not list or len(paths) > 1000
                    or len(paths) != len(expected_ids)):
                return False
            for index, item in enumerate(paths, 1):
                if (type(item) is not dict or set(item) != {'id', 'path'}
                        or item['id'] != f'page-{index}' or item['id'] not in expected_ids
                        or not valid_path(item['path'])):
                    return False
        if type(value['resources']) is not list or len(value['resources']) > 100:
            return False
        seen_resources = set()
        for r in value['resources']:
            if (type(r) is not dict or set(r) != {'page', 'kind', 'count'} or r['page'] not in ids
                    or r['page'] in incomplete_ids
                    or r['kind'] not in ('script', 'stylesheet', 'form', 'api')
                    or type(r['count']) is not int or not 1 <= r['count'] <= 1000):
                return False
            key = (r['page'], r['kind'])
            if key in seen_resources:
                return False
            seen_resources.add(key)
        limits = value['limits']
        prefix = ['lab_only'] if provenance == 'lab' else []
        if 'exclusion_reasons' in value:
            reasons = value['exclusion_reasons']
            names = {'external', 'query_fragment', 'sensitive', 'non_html_resource', 'invalid', 'out_of_scope', 'depth', 'unknown'}
            if (type(reasons) is not dict or set(reasons) != names
                    or any(type(n) is not int or not 0 <= n <= 30000 for n in reasons.values())
                    or sum(reasons.values()) > 30000
                    or type(limits) is not list or len(limits) <= len(prefix)
                    or type(limits[len(prefix)]) is not str
                    or re.fullmatch(r'excluded_links:[0-9]{1,5}', limits[len(prefix)]) is None
                    or sum(reasons.values()) != int(limits[len(prefix)].split(':')[1])):
                return False
        if provenance == 'live' and value['complete'] and (type(limits) is not list or not limits or limits[0] != 'excluded_links:0'):
            return False
        return (type(limits) is list and len(limits) == len(prefix) + 5 and limits[:len(prefix)] == prefix
                and type(limits[len(prefix)]) is str and re.fullmatch(r'excluded_links:[0-9]{1,5}', limits[len(prefix)]) is not None
                and limits[len(prefix) + 1:] == ['no_external_requests', 'no_authentication', 'headers_only_analysis', 'not_a_vulnerability_or_compliance_conclusion'])
    except (KeyError, ValueError, TypeError, OverflowError):
        return False
