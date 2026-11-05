import json
from copy import deepcopy

import pytest

from app import fortress_standard_contract as contract
from app.fortress_checks import evaluate_findings
from app.fortress_single_scope import prepare_single_scope


RAW = json.dumps({'url': 'https://fixture.invalid/private', 'authorized': True, 'method': 'GET'})
PAYLOAD = prepare_single_scope(RAW)


def result():
    findings = evaluate_findings({}, route='[redacted route]', method='GET', date='2026-11-05')
    for f in findings:
        f.update(route_index=1, evidence_code='indeterminate')
    return {'audit_id': '12345678-1234-1234-1234-123456789abc', 'mode': 'standard',
            'started_at': '2026-11-05T10:00:00+00:00', 'finished_at': '2026-11-05T10:00:01+00:00',
            'scope': {'origin': '[redacted]', 'paths': ['[redacted route]']}, 'requests_used': 1,
            'complete': False, 'findings': findings, 'route_execution': [{'route_index': 1, 'state': 'completed'}],
            'limitations': ['Incomplete prototype: CORS and probes not performed; advisory assessment unavailable.',
                            'Value analysis is limited to syntax categories; raw values and policy effectiveness are not established.'],
            'http_status': 200, 'failure_code': 'none'}


def test_strict_projection_preserves_http_date_and_redacts_scope():
    projected = contract.project_strict(result(), PAYLOAD)
    assert projected['http_status'] == 200
    assert projected['started_at'] == '2026-11-05T10:00:00+00:00'
    assert projected['findings'][0]['date'] == '2026-11-05'
    assert 'fixture.invalid' not in repr(projected)
    assert 'private' not in repr(projected)


@pytest.mark.parametrize('mutation', [
    lambda r: r.update(http_status=True),
    lambda r: r.update(http_status=600),
    lambda r: r.update(requests_used=True),
    lambda r: r.update(requests_used=0),
    lambda r: r.update(http_status=302),
    lambda r: r['route_execution'][0].update(route_index=True),
    lambda r: r['findings'][0].update(evidence='secret=unsafe'),
    lambda r: r['findings'][0].update(status='conformant', evidence_code='tls_verified'),
    lambda r: r['findings'][0].update(date='20261105'),
    lambda r: r.update(unexpected='secret'),
])
def test_strict_rejects_incoherent_or_forged_results(mutation):
    report = result()
    mutation(report)
    with pytest.raises(ValueError):
        contract.project_strict(report, PAYLOAD)


@pytest.mark.parametrize('language', ['en', 'fr'])
def test_service_strict_result_retains_derived_codes(language):
    from app import fortress_service as service

    class Transport:
        def __init__(self, *args, **kwargs):
            self.count, self.blocked = 0, False
        def observe_headers(self, method, url):
            assert method == 'GET'
            self.count += 1
            return {'status': 200, 'redirected': False, 'outcome': 'ok',
                    'tls': {'certificate': 'verified', 'protocol': 'TLSv1.3'},
                    'security_headers': {'hsts': 'present', 'csp': 'invalid',
                                         'x_content_type_options': 'present', 'referrer_policy': 'absent'},
                    'header_value_facts': {'x_content_type_options': 'recognized_nosniff'},
                    'cookies': {'count': 2, 'missing_secure': 1, 'missing_httponly': 0,
                                'missing_samesite': 0, 'indeterminate': 0}}

    report = service._audit_single_with_factory(RAW, factory=Transport, language=language)
    out = contract.project_strict(report, PAYLOAD)
    findings = {f['id']: f for f in out['findings']}
    assert [(findings[n]['status'], findings[n]['evidence_code']) for n in
            ('https_tls', 'hsts', 'csp', 'x_content_type_options', 'referrer_policy', 'cookie_attributes')] == [
            ('conformant', 'tls_verified'), ('indeterminate', 'header_syntax_recognized'),
            ('attention', 'header_invalid'), ('conformant', 'header_valid'),
            ('attention', 'header_absent'), ('attention', 'cookie_attributes_missing')]
    assert 'fixture.invalid' not in repr(out)


def test_observed_refusal_retains_403_but_never_confirms():
    from app import fortress_service as service
    class Refused:
        def __init__(self, *args, **kwargs):
            self.count, self.blocked = 0, False
        def observe_headers(self, method, url):
            self.count = 1
            self.blocked = True
            return {'status': 403, 'redirected': False, 'outcome': 'http_refused'}
    report = service._audit_single_with_factory(RAW, factory=Refused)
    out = contract.project_strict(report, PAYLOAD)
    assert out['http_status'] == 403
    assert out['route_execution'][0]['state'] in ('blocked', 'indeterminate')
    assert all(f['status'] == 'indeterminate' for f in out['findings'])


def test_blocked_200_is_rejected():
    report = result()
    report['route_execution'][0]['state'] = 'blocked'
    with pytest.raises(ValueError):
        contract.project_strict(report, PAYLOAD)


def test_redirect_and_incomplete_do_not_claim_conformity():
    for state, status, count in [('redirected', 302, 1), ('blocked', None, 1), ('indeterminate', None, 1), ('not_started', None, 0)]:
        report = result()
        report['route_execution'][0]['state'] = state
        report.update(http_status=status, requests_used=count, failure_code='none' if state == 'redirected' else 'unknown')
        out = contract.project_strict(report, PAYLOAD)
        assert out['http_status'] == status
        assert all(f['status'] == 'indeterminate' for f in out['findings'])
