"""Pure HEAD facts and separately attributed synthetic fixture reports.

The conservative HTTP/1.x subset is that accepted by fortress_live.parse_head.
Facts describe bytes, never their origin. Validation checks consistency, not
truth. Fixture reports retain their original synthetic-only provenance.
"""
import re
from .fortress_live import parse_head
from .fortress_mvp import _csp_details, _CSP_DIRECTIVES

TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
COOKIE = re.compile(r'[\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]*\Z')
ROUTE = 'fixture-route-1'


def validate_declaration(value):
    """Validate an untrusted metadata declaration, not a report or evidence.

    Declared kind/state are caller claims only. There is no transport, TLS
    attestation, payload import or promotion from declarations to reports.
    """
    if type(value) is not dict or set(value) != {'schema_version', 'provenance', 'execution', 'scope'}:
        return False
    p, e = value['provenance'], value['execution']
    if type(p) is not dict or set(p) != {'declared_kind', 'attestation'} or type(e) is not dict or set(e) != {'declared_state', 'request_sent'}:
        return False
    return (value['schema_version'] == 'fortress.declaration/1' and
            type(p['declared_kind']) is str and p['declared_kind'] in ('fixture', 'live', 'imported') and p['attestation'] == 'none' and
            type(e['declared_state']) is str and e['declared_state'] in ('not_performed', 'blocked', 'incomplete', 'completed', 'failed') and
            e['request_sent'] == 'unknown' and value['scope'] == {'route_id': ROUTE, 'method': 'HEAD'})


def hsts(values):
    if not values:
        return 'absent'
    if len(values) != 1 or not values[0].isascii():
        return 'indeterminate'
    seen, age = set(), None
    for part in values[0].split(';'):
        if not part.strip():
            continue
        name, eq, val = part.strip().partition('=')
        name, val = name.strip().lower(), val.strip()
        if not TOKEN.fullmatch(name) or name in seen:
            return 'indeterminate'
        seen.add(name)
        if name == 'max-age':
            if not eq or not re.fullmatch(r'[0-9]{1,12}', val):
                return 'indeterminate'
            age = int(val)
        elif name in ('includesubdomains', 'preload'):
            if eq:
                return 'indeterminate'
        elif eq and not TOKEN.fullmatch(val):
            return 'indeterminate'
    return 'indeterminate' if age is None else ('disabled' if age == 0 else 'positive')


def csp(values):
    return {'missing': 'absent', 'present': 'present', 'indeterminate': 'indeterminate'}[_csp_details(values)['status']]


def csp_projection(values):
    details = _csp_details(values)
    return [{'directive': item['directive'], 'unsafe_inline': item['inline']}
            for item in details['directives']]


def csp_effective(values):
    if _csp_details(values)['status'] != 'present':
        return []
    directives = {}
    for part in values[0].split(';'):
        tokens = part.split()
        if tokens:
            directives[tokens[0].lower()] = [v.lower() for v in tokens[1:]]
    result = []
    for kind in ('script', 'style'):
        for suffix in ('elem', 'attr'):
            for name in (kind + '-src-' + suffix, kind + '-src', 'default-src'):
                if name in directives:
                    sources = directives[name]
                    if "'unsafe-inline'" in sources:
                        uncertain = any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in sources)
                        result.append({'sink': kind + '-' + suffix, 'directive': name,
                                       'mode': 'uncertain' if uncertain else 'review'})
                    break
    return result


def cookies(values):
    def unknown():
        return {'state': 'indeterminate', 'count': len(values), 'secure': None, 'httponly': None, 'samesite': None}
    if not values:
        return {'state': 'none_observed', 'count': 0, 'secure': None, 'httponly': None, 'samesite': None}
    counts = dict.fromkeys(('secure', 'httponly', 'samesite'), 0)
    for value in values:
        parts = value.split(';')
        name, eq, val = parts[0].strip().partition('=')
        if not eq or not TOKEN.fullmatch(name) or not COOKIE.fullmatch(val):
            return unknown()
        seen = set()
        for part in parts[1:]:
            name, eq, val = part.strip().partition('=')
            name = name.strip().lower()
            if not TOKEN.fullmatch(name) or name in seen or (eq and (not val.strip() or not re.fullmatch(r'[\x20-\x3a\x3c-\x7e]+', val))):
                return unknown()
            seen.add(name)
            if name in counts:
                if (name == 'samesite' and (not eq or val.strip().lower() not in ('strict', 'lax', 'none'))) or (name != 'samesite' and eq):
                    return unknown()
                counts[name] += 1
    return {'state': 'observed', 'count': len(values), **counts}


def cookie_prefix(values, summary):
    if summary['state'] != 'observed':
        return {'state': summary['state'], 'violations': None}
    violations = 0
    for value in values:
        parts = value.split(';')
        cookie_name = parts[0].strip().partition('=')[0]
        attrs = {p.strip().partition('=')[0].strip().lower(): p.strip().partition('=')[2].strip() for p in parts[1:]}
        if cookie_name.startswith('__Host-'):
            violations += int('secure' not in attrs or 'domain' in attrs or attrs.get('path') != '/')
        elif cookie_name.startswith('__Secure-'):
            violations += int('secure' not in attrs)
    return {'state': 'observed', 'violations': violations}


def findings(obs):
    result = []
    if obs['hsts'] in ('absent', 'disabled'):
        suffix = 'header_absent' if obs['hsts'] == 'absent' else 'disabled'
        result.append({'rule_id': 'hsts.' + suffix + '.v1', 'qualification': 'confirmed', 'priority': 'unclassified',
                       'evidence': obs['hsts'], 'route_id': ROUTE, 'recommendation': 'review_hsts_for_route', 'limit': 'head_response_only'})
    for field, label in (('csp_effective', 'active'), ('csp_report_only_effective', 'report_only')):
        emitted = set()
        for item in obs[field]:
            key = (item['directive'], item['mode'])
            if key not in emitted:
                emitted.add(key)
                result.append({'rule_id': 'csp.' + label + '_inline.v1', 'qualification': 'investigate', 'priority': 'unclassified',
                               'evidence': item['directive'], 'route_id': ROUTE, 'recommendation': 'review_inline_in_context' if item['mode'] == 'review' else 'review_policy_semantics',
                               'limit': 'effect_not_determined'})
    c = obs['cookies']
    if c['state'] == 'indeterminate':
        result.append({'rule_id': 'cookie.syntax_indeterminate.v1', 'qualification': 'investigate', 'priority': 'unclassified',
                       'evidence': 'syntax_indeterminate', 'route_id': ROUTE, 'recommendation': 'review_cookie_syntax_in_context', 'limit': 'acceptance_and_usage_unknown'})
    if c['state'] == 'observed':
        for key in ('secure', 'httponly'):
            if c[key] < c['count']:
                result.append({'rule_id': 'cookie.missing_' + key + '.v1', 'qualification': 'investigate', 'priority': 'unclassified',
                               'evidence': 'attribute_missing_on_some', 'route_id': ROUTE, 'recommendation': 'review_cookie_attributes_in_context', 'limit': 'acceptance_and_usage_unknown'})
        if obs['cookie_prefix']['violations']:
            result.append({'rule_id': 'cookie.prefix_requirements.v1', 'qualification': 'investigate', 'priority': 'unclassified',
                           'evidence': 'prefix_requirements_not_met', 'route_id': ROUTE, 'recommendation': 'review_cookie_prefix_in_context', 'limit': 'acceptance_and_usage_unknown'})
    return result


def empty():
    return {'http_status': None, 'hsts': 'not_evaluated', 'csp': 'not_evaluated', 'csp_report_only': 'not_evaluated',
            'csp_directives': [], 'csp_report_only_directives': [], 'csp_effective': [], 'csp_report_only_effective': [], 'cookie_prefix': {'state': 'not_evaluated', 'violations': None},
            'x_content_type_options': 'not_evaluated', 'referrer_policy': 'not_evaluated', 'permissions_policy': 'not_evaluated',
            'cookies': {'state': 'not_evaluated', 'count': None, 'secure': None, 'httponly': None, 'samesite': None}}


def _analyze_fixture(data):
    result = {'schema_version': 'fortress.report/1', 'provenance': {'kind': 'fixture', 'attestation': 'none'},
              'scope': {'route_id': ROUTE, 'method': 'HEAD'},
              'execution': {'state': 'incomplete', 'cause': 'invalid_or_incomplete_head', 'request_sent': 'unknown'},
              'observations': empty(), 'findings': [],
              'limits': ['synthetic_only', 'head_response_only', 'no_live_attestation', 'no_global_compliance']}
    if type(data) is not bytes:
        return result
    # The transport uses ValueError for framing and may also raise it
    # internally. Without a typed transport error, its cause is indeterminate;
    # this legacy cause must not be interpreted as proof of bad framing.
    try:
        status, _ = parse_head(data)
    except ValueError:
        return result
    facts = analyze_head_facts(data)
    result['observations'] = facts['observations']
    result['findings'] = findings(facts['observations'])
    result['execution'] = {'state': 'completed', 'cause': 'none', 'request_sent': 'unknown'}
    return result


def _analyze_head_facts(data):
    "Pure projection; no claim about the source of supplied bytes."
    status, _ = parse_head(data)
    values = {}
    for line in data.split(b'\r\n')[1:-2]:
        name, value = line.split(b':', 1)
        values.setdefault(name.lower(), []).append(value.strip().decode('latin1'))
    get = lambda name: values.get(name, [])
    obs = empty()
    obs.update(http_status=status, hsts=hsts(get(b'strict-transport-security')),
               csp=csp(get(b'content-security-policy')), csp_report_only=csp(get(b'content-security-policy-report-only')),
               csp_directives=csp_projection(get(b'content-security-policy')),
               csp_report_only_directives=csp_projection(get(b'content-security-policy-report-only')),
               csp_effective=csp_effective(get(b'content-security-policy')),
               csp_report_only_effective=csp_effective(get(b'content-security-policy-report-only')),
               cookies=cookies(get(b'set-cookie')))
    obs['cookie_prefix'] = cookie_prefix(get(b'set-cookie'), obs['cookies'])
    for key, name in (('x_content_type_options', b'x-content-type-options'), ('referrer_policy', b'referrer-policy'), ('permissions_policy', b'permissions-policy')):
        vals = get(name)
        obs[key] = 'absent' if not vals else ('present' if len(vals) == 1 else 'indeterminate')
    items = findings(obs)
    for item in items:
        item['route_id'] = 'head-route-1'
    return {'schema_version': 'fortress.head-facts/1', 'observations': obs, 'findings': items}


def analyze_head_facts(data):
    """Closed rejection for malformed input or analysis failure."""
    try:
        return _analyze_head_facts(data)
    except Exception:
        return None


def analyze_fixture(data):
    try:
        return _analyze_fixture(data)
    except Exception:
        return {'schema_version': 'fortress.report/1', 'provenance': {'kind': 'fixture', 'attestation': 'none'},
                'scope': {'route_id': ROUTE, 'method': 'HEAD'},
                'execution': {'state': 'failed', 'cause': 'internal_error_unknown', 'request_sent': 'unknown'},
                'observations': {'http_status': None, 'hsts': 'not_evaluated', 'csp': 'not_evaluated', 'csp_report_only': 'not_evaluated',
                    'csp_directives': [], 'csp_report_only_directives': [], 'csp_effective': [], 'csp_report_only_effective': [],
                    'cookie_prefix': {'state': 'not_evaluated', 'violations': None}, 'x_content_type_options': 'not_evaluated',
                    'referrer_policy': 'not_evaluated', 'permissions_policy': 'not_evaluated',
                    'cookies': {'state': 'not_evaluated', 'count': None, 'secure': None, 'httponly': None, 'samesite': None}}, 'findings': [],
                'limits': ['synthetic_only', 'head_response_only', 'no_live_attestation', 'no_global_compliance']}


def validate_report(report):
    """Check fixture shape and consistency, not authenticity; live/import unsupported."""
    try:
        if type(report) is not dict or set(report) != {'schema_version', 'provenance', 'scope', 'execution', 'observations', 'findings', 'limits'}:
            return False
        if (report['schema_version'] != 'fortress.report/1' or report['provenance'] != {'kind': 'fixture', 'attestation': 'none'}
            or report['scope'] != {'route_id': ROUTE, 'method': 'HEAD'}
            or report['limits'] != ['synthetic_only', 'head_response_only', 'no_live_attestation', 'no_global_compliance']):
            return False
        obs = report['observations']
        if type(obs) is not dict or set(obs) != set(empty()):
            return False
        if report['execution'] in ({'state': 'incomplete', 'cause': 'invalid_or_incomplete_head', 'request_sent': 'unknown'},
                                   {'state': 'failed', 'cause': 'internal_error_unknown', 'request_sent': 'unknown'}):
            return obs == empty() and report['findings'] == []
        if report['execution'] != {'state': 'completed', 'cause': 'none', 'request_sent': 'unknown'}:
            return False
        return _validate_completed(obs, report['findings'])
    except (KeyError, TypeError, ValueError):
        return False


def _validate_completed(obs, items, route=ROUTE):
    try:
        if type(obs['http_status']) is not int or not 200 <= obs['http_status'] <= 599:
            return False
        if obs['hsts'] not in ('absent', 'positive', 'disabled', 'indeterminate'):
            return False
        if any(obs[k] not in ('absent', 'present', 'indeterminate') for k in ('csp', 'csp_report_only', 'x_content_type_options', 'referrer_policy', 'permissions_policy')):
            return False
        for state, field in (('csp', 'csp_directives'), ('csp_report_only', 'csp_report_only_directives')):
            directives = obs[field]
            if type(directives) is not list or (obs[state] != 'present' and directives) or len(directives) > len(_CSP_DIRECTIVES):
                return False
            seen = set()
            for item in directives:
                if (type(item) is not dict or set(item) != {'directive', 'unsafe_inline'} or
                    item['directive'] not in _CSP_DIRECTIVES or item['directive'] in seen or type(item['unsafe_inline']) is not bool):
                    return False
                seen.add(item['directive'])
        for state, projected, field in (('csp', 'csp_directives', 'csp_effective'), ('csp_report_only', 'csp_report_only_directives', 'csp_report_only_effective')):
            effective = obs[field]
            if type(effective) is not list or len(effective) > 4 or (obs[state] != 'present' and effective):
                return False
            seen = set()
            modes = {}
            by_name = {x['directive']: x['unsafe_inline'] for x in obs[projected]}
            for item in effective:
                if type(item) is not dict or set(item) != {'sink', 'directive', 'mode'} or item['sink'] not in ('script-elem', 'script-attr', 'style-elem', 'style-attr') or item['sink'] in seen or item['mode'] not in ('review', 'uncertain'):
                    return False
                kind, suffix = item['sink'].split('-')
                applicable = next((n for n in (kind + '-src-' + suffix, kind + '-src', 'default-src') if n in by_name), None)
                if item['directive'] != applicable or not by_name.get(applicable):
                    return False
                if applicable in modes and modes[applicable] != item['mode']:
                    return False
                modes[applicable] = item['mode']
                seen.add(item['sink'])
            for kind in ('script', 'style'):
                for suffix in ('elem', 'attr'):
                    applicable = next ( (n for n in (kind + '-src-' + suffix, kind + '-src', 'default-src') if n in by_name), None)
                    if by_name.get(applicable) and kind + '-' + suffix not in seen:
                        return False
        c = obs['cookies']
        if type(c) is not dict or set(c) != {'state', 'count', 'secure', 'httponly', 'samesite'} or type(c['count']) is not int or not 0 <= c['count'] <= 16384:
            return False
        keys = ('secure', 'httponly', 'samesite')
        if c['state'] == 'none_observed':
            if c['count'] != 0 or any(c[k] is not None for k in keys):
                return False
        elif c['state'] == 'indeterminate':
            if c['count'] < 1 or any(c[k] is not None for k in keys):
                return False
        elif c['state'] == 'observed':
            if c['count'] < 1 or any(type(c[k]) is not int or not 0 <= c[k] <= c['count'] for k in keys):
                return False
        else:
            return False
        p = obs['cookie_prefix']
        if type(p) is not dict or set(p) != {'state', 'violations'} or p['state'] != c['state']:
            return False
        if c['state'] == 'observed':
            if type(p['violations']) is not int or not 0 <= p['violations'] <= c['count']:
                return False
        elif p['violations'] is not None:
            return False
        expected = findings(obs)
        for item in expected:
            item['route_id'] = route
        return type(items) is list and items == expected
    except (KeyError, TypeError, ValueError):
        return False


def validate_head_facts(value):
    try:
        return (type(value) is dict and set(value) == {"schema_version", "observations", "findings"}
                and value["schema_version"] == "fortress.head-facts/1"
                and type(value["observations"]) is dict and set(value["observations"]) == set(empty())
                and _validate_completed(value["observations"], value["findings"], 'head-route-1'))
    except Exception:
        return False
