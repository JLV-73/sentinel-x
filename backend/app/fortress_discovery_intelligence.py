"""Passive, offline projection of caller-collected HTTP responses.

analyze_pages accepts a list of dicts with exactly route, observed_at, status,
complete and headers. Route must identify an effective page (never the
pre-redirect route), and contain no query/fragment. Paths are never returned:
each output route is a positional page-N label scoped to this invocation.
Headers are an ephemeral list of (name, value) strings, including duplicates.
No source authenticity, transport framing, authorization, TLS or redirect is
attested here. Method is unknown; no GET or HEAD is asserted. A complete
response and its effective route are caller claims. Incomplete responses must
have null status and empty headers. Callers retain responsibility for inputs,
their frames and logs. No network is performed.
"""
from datetime import datetime
import re

from . import fortress_advanced_core as core

_ROUTE = re.compile(r'/[A-Za-z0-9._~/-]{0,255}\Z')
_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_LIMITS = ['caller_declared_provenance', 'effective_route_declared_by_caller',
           'response_headers_only', 'method_unknown', 'positional_route_labels',
           'no_vulnerability_or_compliance_conclusion']


def analyze_pages(pages):
    """Project pages without exposing input on controlled failure frames.

    Output route labels are opaque, one-based input positions, not paths.
    Callers own their inputs and must not log them or capture their own locals.
    """
    try:
        return _analyze_pages(pages)
    except Exception:
        pass
    del pages
    raise ValueError('invalid or unprocessable pages')


def _analyze_pages(pages):
    """Return JSON-compatible facts; input is neither mutated nor retained.

    `complete` must represent the collector's verified complete response. A
    403 is a distinct access-denied observation, not a page security verdict.
    Duplicate routes are rejected: one result corresponds to one effective page.
    """
    if type(pages) is not list or len(pages) > 100:
        raise ValueError('invalid pages')
    output, seen = [], set()
    for index, page in enumerate(pages, 1):
        if type(page) is not dict or set(page) != {'route', 'observed_at', 'status', 'complete', 'headers'}:
            raise ValueError('invalid page')
        route, date, status, complete, headers = (page[k] for k in ('route', 'observed_at', 'status', 'complete', 'headers'))
        if type(route) is not str or not _ROUTE.fullmatch(route) or route.startswith('//') or route in seen:
            raise ValueError('invalid route')
        seen.add(route)
        if type(date) is not str or len(date) > 40:
            raise ValueError('invalid timestamp')
        try:
            timestamp = datetime.fromisoformat(date.replace('Z', '+00:00'))
            if timestamp.tzinfo is None or timestamp.utcoffset() is None:
                raise ValueError
        except ValueError:
            raise ValueError('invalid timestamp') from None
        if type(complete) is not bool or (status is not None and (type(status) is not int or not 200 <= status <= 599)) or (complete and status is None):
            raise ValueError('invalid execution')
        if type(headers) is not list or len(headers) > 256:
            raise ValueError('invalid headers')
        if not complete and (status is not None or headers):
            raise ValueError('inconsistent incomplete response')
        values = {}
        size = 0
        for pair in headers:
            if type(pair) not in (list, tuple) or len(pair) != 2:
                raise ValueError('invalid headers')
            name, value = pair
            if type(name) is not str or type(value) is not str or len(name) + len(value) > 32768 or not _TOKEN.fullmatch(name) or not value.isascii() or any(ord(c) < 32 and c != '\t' or ord(c) == 127 for c in value):
                raise ValueError('invalid headers')
            size += len(name) + len(value)
            if size > 32768:
                raise ValueError('invalid headers')
            values.setdefault(name.lower(), []).append(value)
        state = ('incomplete' if not complete else 'access_denied' if status == 403
                 else 'redirected' if 300 <= status < 400
                 else 'http_error' if status >= 400 else 'complete')
        route_label = f'page-{index}'
        entry = {'route': route_label, 'observed_at': timestamp.isoformat(), 'status': status, 'state': state,
                 'method': 'unknown',
                 'provenance': {'kind': 'caller_declared', 'attestation': 'none'},
                 'confidence': 'not_evaluated', 'observations': None, 'findings': [], 'limits': list(_LIMITS)}
        if state == 'complete':
            get = lambda name: values.get(name, [])
            obs = core.empty()
            obs.update(http_status=status, hsts=core.hsts(get('strict-transport-security')),
                       csp=core.csp(get('content-security-policy')),
                       csp_report_only=core.csp(get('content-security-policy-report-only')),
                       csp_directives=core.csp_projection(get('content-security-policy')),
                       csp_report_only_directives=core.csp_projection(get('content-security-policy-report-only')),
                       csp_effective=core.csp_effective(get('content-security-policy')),
                       csp_report_only_effective=core.csp_effective(get('content-security-policy-report-only')),
                       cookies=core.cookies(get('set-cookie')))
            obs['cookie_prefix'] = core.cookie_prefix(get('set-cookie'), obs['cookies'])
            for key, name in (('x_content_type_options', 'x-content-type-options'), ('referrer_policy', 'referrer-policy'), ('permissions_policy', 'permissions-policy')):
                vals = get(name)
                obs[key] = 'absent' if not vals else 'present' if len(vals) == 1 else 'indeterminate'
            findings = core.findings(obs)
            for finding in findings:
                finding.pop('route_id')
                finding.update(route=route_label, confidence='caller_declared', provenance='response_headers')
                if finding['limit'] == 'head_response_only':
                    finding['limit'] = 'response_headers_only'
            entry.update(observations=obs, findings=findings, confidence='caller_declared')
        output.append(entry)
    return {'schema_version': 'fortress.discovery-intelligence/1', 'pages': output,
            'limits': list(_LIMITS)}
