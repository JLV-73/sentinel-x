"""Offline projection of closed synthetic fixture reports; no attestation or IO."""
from copy import deepcopy
from .fortress_advanced_core import validate_report, findings


def _plain(value, depth=0):
    if depth > 12:
        return False
    if value is None or type(value) in (bool, int):
        return True
    if type(value) is str:
        return len(value) <= 128
    if type(value) is list:
        return len(value) <= 256 and all(_plain(v, depth + 1) for v in value)
    if type(value) is dict:
        return len(value) <= 64 and all(type(k) is str and len(k) <= 128 and _plain(v, depth + 1) for k, v in value.items())
    return False


def adapt_fixture(report):
    """Return a closed rejection instead of exposing adapter traceback locals.

    This cannot erase references or traceback frames owned by the caller.
    """
    try:
        if not _plain(report) or not validate_report(report):
            return {'error': 'invalid_sanitized_report'}
        report = deepcopy(report)
        report['schema_version'] = 'fortress.adapter/1'
        report['provenance'] = {'declared_kind': 'fixture', 'attestation': 'none'}
        return report
    except Exception:
        return {'error': 'invalid_sanitized_report'}


def _adapt_declared(report, kind):
    try:
        result = adapt_fixture(report)
        if result == {'error': 'invalid_sanitized_report'}:
            return result
        result['provenance']['declared_kind'] = kind
        result['execution']['declared_state'] = result['execution'].pop('state')
        for finding in result['findings']:
            finding['qualification'] = 'declared_unverified'
        result['limits'] = ['synthetic_only'] + ['declared_unverified', 'head_response_only', 'no_live_attestation', 'no_global_compliance']
        return result
    except Exception:
        return {'error': 'invalid_sanitized_report'}


def adapt_live(report):
    """Synthetic sanitized inputs only; live is a claim, never an attestation."""
    return _adapt_declared(report, 'live')


def adapt_imported(report):
    """Import only the closed sanitized vocabulary; all evidence is unverified."""
    return _adapt_declared(report, 'imported')


def validate_adapter(value):
    """Validate closed structure and consistency, not origin or truth."""
    try:
        if not _plain(value) or type(value) is not dict or value.get('schema_version') != 'fortress.adapter/1':
            return False
        provenance = value.get('provenance')
        if type(provenance) is not dict or set(provenance) != {'declared_kind', 'attestation'} or provenance['attestation'] != 'none':
            return False
        kind = provenance['declared_kind']
        if kind not in ('fixture', 'live', 'imported'):
            return False
        candidate = deepcopy(value)
        candidate['schema_version'] = 'fortress.report/1'
        candidate['provenance'] = {'kind': 'fixture', 'attestation': 'none'}
        if kind != 'fixture':
            expected_limits = ['synthetic_only'] + ['declared_unverified', 'head_response_only', 'no_live_attestation', 'no_global_compliance']
            if candidate['limits'] != expected_limits:
                return False
            execution = candidate['execution']
            if type(execution) is not dict or set(execution) != {'declared_state', 'cause', 'request_sent'}:
                return False
            execution['state'] = execution.pop('declared_state')
            expected = findings(candidate['observations']) if execution['state'] == 'completed' else []
            declared = deepcopy(expected)
            for item in declared:
                item['qualification'] = 'declared_unverified'
            if candidate['findings'] != declared:
                return False
            candidate['findings'] = expected
            candidate['limits'] = ['synthetic_only', 'head_response_only', 'no_live_attestation', 'no_global_compliance']
        return validate_report(candidate)
    except (KeyError, TypeError, ValueError, IndexError):
        return False
