"""Pure offline experimental comparison; NOT SAFE FOR INTEGRATION OR ACTIVATION.

Known unresolved issues: caller attestations cannot authenticate provenance; input
object size is not bounded; duplicate contradictory GHSA associations and
malformed active entries can still produce incomplete or misleading candidates.
Do not expose this function through an API or connect it to production.

match_cached(component, cache) accepts caller-attested, already-projected cache
records, NOT a database or a URL. The caller must obtain a bounded consistent
snapshot and independently verify source, provenance, freshness and completeness;
boolean attestations are not cryptographic verification. Never use banners.
Only exact, lowercase npm identities and stable numeric x.y.z versions are
supported. Range grammar is one to four space-separated comparisons using =,
>, >=, <, <= or an exact bare version. No prerelease, build, OR, caret, tilde,
wildcard or partial version. Outputs are candidate hints, never vulnerability
or safety conclusions. No claim is made about completeness of GHSA cache.
"""
import re
from datetime import datetime

_GHSA = re.compile(r'GHSA-[23456789cfghjmpqrvwx]{4}(?:-[23456789cfghjmpqrvwx]{4}){2}', re.ASCII)
_CVE = re.compile(r'CVE-[0-9]{4}-[0-9]{4,12}', re.ASCII)
_PACKAGE = re.compile(r'(?:@[a-z0-9][a-z0-9._-]{0,99}/)?[a-z0-9][a-z0-9._-]{0,99}', re.ASCII)
_VERSION = re.compile(r'(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})', re.ASCII)
_CLAUSE = re.compile(r'(>=|<=|>|<|=)?[ ]*((?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8}))', re.ASCII)
_RANGE = re.compile(r'(?:>=|<=|>|<|=)?[ ]*(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})(?:[ ]+(?:>=|<=|>|<|=)?[ ]*(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})){0,3}', re.ASCII)


def _version(value):
    if not isinstance(value, str) or len(value) > 29 or not _VERSION.fullmatch(value):
        return None
    return tuple(map(int, value.split('.')))


def _compare(version, expression):
    if not isinstance(expression, str) or len(expression) > 160 or not _RANGE.fullmatch(expression):
        return None
    clauses = list(_CLAUSE.finditer(expression))
    matches = []
    for match in clauses:
        operator, raw = match.groups()
        target = _version(raw)
        if target is None:
            return None
        matches.append({'=': version == target, '>': version > target, '>=': version >= target,
                        '<': version < target, '<=': version <= target}[operator or '='])
    return all(matches)


def _reviewed(value):
    if not isinstance(value, str) or len(value) > 40 or not value.endswith('Z'):
        return False
    try:
        datetime.fromisoformat(value[:-1] + '+00:00')
        return True
    except ValueError:
        return False


def match_cached(component, cache):
    """Return {status, reason, advisories}; all free-form inputs are discarded.

    component: ecosystem, package, version, source_verified, mapping_verified.
    cache: source='ghsa', current, provenance_verified, complete, advisories.
    The four attestations must be literally True and belong to a trusted caller.
    Caller is responsible for snapshot and original provenance verification.
    """
    def unknown(reason):
        return {'status': 'indeterminate', 'reason': reason, 'advisories': []}

    if not isinstance(component, dict) or not isinstance(cache, dict):
        return unknown('invalid_input')
    package = component.get('package')
    version = _version(component.get('version'))
    if (component.get('ecosystem') != 'npm' or not isinstance(package, str) or
            len(package) > 201 or not _PACKAGE.fullmatch(package) or version is None or
            component.get('source_verified') is not True or component.get('mapping_verified') is not True):
        return unknown('component_unverified')
    records = cache.get('advisories')
    if (cache.get('source') != 'ghsa' or cache.get('current') is not True or
            cache.get('provenance_verified') is not True or cache.get('complete') is not True or
            not isinstance(records, list) or len(records) > 100):
        return unknown('cache_unverified')
    candidates = {}
    partial = False
    for advisory in records:
        if not isinstance(advisory, dict):
            continue
        ghsa, cve = advisory.get('ghsa_id'), advisory.get('cve_id')
        if (not isinstance(ghsa, str) or not _GHSA.fullmatch(ghsa) or
                not isinstance(cve, str) or not _CVE.fullmatch(cve) or
                advisory.get('type') != 'reviewed' or not _reviewed(advisory.get('github_reviewed_at')) or
                'withdrawn_at' not in advisory or advisory['withdrawn_at'] is not None or
                advisory.get('html_url') != 'https://github.com/advisories/' + ghsa):
            continue
        identifiers = advisory.get('identifiers')
        if (not isinstance(identifiers, list) or len(identifiers) != 2 or
                any(not isinstance(item, dict) for item in identifiers) or
                {(item.get('type'), item.get('value')) for item in identifiers
                 if isinstance(item.get('type'), str) and isinstance(item.get('value'), str)} !=
                {('GHSA', ghsa), ('CVE', cve)}):
            partial = True
            continue
        vulnerabilities = advisory.get('vulnerabilities')
        if not isinstance(vulnerabilities, list) or len(vulnerabilities) > 100:
            continue
        for entry in vulnerabilities:
            if not isinstance(entry, dict) or not isinstance(entry.get('package'), dict):
                continue
            identity = entry['package']
            if identity.get('ecosystem') != 'npm' or identity.get('name') != package:
                continue
            comparison = _compare(version, entry.get('vulnerable_version_range'))
            if comparison is None:
                partial = True
            elif comparison is True:
                candidates[(ghsa, cve)] = {'ghsa_id': ghsa, 'cve_id': cve,
                                           'reference': 'https://github.com/advisories/' + ghsa}
    if partial:
        return {'status': 'indeterminate', 'reason': 'partial_unsupported',
                'advisories': [candidates[key] for key in sorted(candidates)]}
    if not candidates:
        return unknown('no_supported_candidate')
    return {'status': 'potential', 'reason': 'advisory_candidate',
            'advisories': [candidates[key] for key in sorted(candidates)]}
