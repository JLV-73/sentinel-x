import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location('fortress_checks', Path(__file__).parents[1] / 'app' / 'fortress_checks.py')
checks = importlib.util.module_from_spec(spec)
if spec.loader and Path(spec.origin).exists():
    spec.loader.exec_module(checks)


def test_unperformed_checks_are_indeterminate():
    results = checks.evaluate_findings({}, route='/safe', method='GET', date='2026-10-29')
    assert results and all(item['status'] == 'indeterminate' for item in results)


def result(name, fact):
    return next(x for x in checks.evaluate_findings({name: fact}, route='/private', method='GET', date='2026-10-29') if x['id'] == name)


def test_tls_failure_is_not_a_proven_missing_protection():
    assert result('https_tls', {'complete': True, 'observed': False})['status'] == 'indeterminate'


def test_headers_and_cookie_signal():
    for name in ('hsts', 'csp', 'x_content_type_options', 'referrer_policy', 'permissions_policy'):
        assert result(name, {'complete': True, 'observed': True})['status'] == 'conformant'
        assert result(name, {'complete': True, 'observed': False})['status'] == 'attention'
    assert result('https_tls', {'complete': True, 'observed': True})['status'] == 'conformant'
    for name in ('cookie_attributes', 'third_party_scripts', 'debug_info', 'directory_index'):
        extra = {'cookie_count': 1} if name == 'cookie_attributes' else {}
        assert result(name, {'complete': True, 'observed': True, **extra})['status'] == 'attention'
        assert result(name, {'complete': True, 'observed': False, **extra})['status'] == 'conformant'


def test_cookie_evidence_has_count_without_cookie_value():
    item = result('cookie_attributes', {'complete': True, 'observed': True, 'cookie_count': 2, 'value': 'SECRET_VALUE'})
    assert 'Cookie count: 2' in item['evidence']
    assert 'SECRET_VALUE' not in str(item)


def test_cookie_set_requires_nonempty_typed_count():
    for count in (None, 0, -1, True, '1'):
        assert result('cookie_attributes', {'complete': True, 'observed': False, 'cookie_count': count})['status'] == 'indeterminate'


def test_blocked_or_failed_observation_never_classified():
    for state in ('blocked', 'error', 'truncated', 'not_performed'):
        assert result('hsts', {'complete': True, 'observed': True, 'state': state})['status'] == 'indeterminate'


def test_incomplete_and_malformed_never_conformant():
    for fact in ({}, {'complete': False, 'observed': True}, {'complete': 1, 'observed': True}, {'complete': True, 'observed': 1}):
        assert result('hsts', fact)['status'] == 'indeterminate'


def test_cors_requires_coherent_observation_and_probe_proof():
    base = {'complete': True, 'origin_tested': True, 'same_endpoint': True, 'acao': 'wildcard', 'credentials': False, 'observed': True, 'kind': 'wildcard'}
    assert result('cors', base)['status'] == 'attention'
    for change in ({'observed': None}, {'observed': False}, {'acao': 'none'}, {'origin_tested': False}, {'same_endpoint': False}, {'credentials': None}):
        assert result('cors', {**base, **change})['status'] == 'indeterminate'
    assert result('cors', {'complete': True, 'kind': 'none'})['status'] == 'indeterminate'
    assert result('cors', {**base, 'kind': 'none', 'acao': 'none', 'observed': False})['status'] == 'conformant'


def test_active_probes_without_execution_proof_are_indeterminate():
    for name in ('redirect', 'reflection'):
        for observed in (True, False):
            assert result(name, {'complete': True, 'observed': observed})['status'] == 'indeterminate'


def test_static_redirect_witness_requires_independent_control():
    fact = {'complete': True, 'probe_performed': True, 'parameter_authorized': True,
            'witness_checked': True, 'destination_followed': False, 'observed': True}
    assert result('redirect', fact)['status'] == 'indeterminate'
    control = {'control_complete': True, 'control_same_endpoint': True,
               'control_parameter_changed_only': True, 'control_witness_match': False}
    for change in ({'control_complete': False}, {'control_same_endpoint': False},
                   {'control_parameter_changed_only': False}, {'control_witness_match': True},
                   {'control_witness_match': 0}):
        assert result('redirect', {**fact, **control, **change})['status'] == 'indeterminate'
    assert result('redirect', {**fact, **control})['status'] == 'confirmed'


def test_cors_redirect_and_reflection_classifications():
    redirect = {'complete': True, 'probe_performed': True, 'parameter_authorized': True, 'witness_checked': True, 'destination_followed': False}
    reflection_fact = {'complete': True, 'probe_performed': True, 'parameter_authorized': True, 'marker_checked': True}
    control = {'control_complete': True, 'control_same_endpoint': True, 'control_parameter_changed_only': True, 'control_witness_match': False}
    assert result('redirect', {**redirect, **control, 'observed': True})['status'] == 'confirmed'
    assert result('redirect', {**redirect, 'observed': False})['status'] == 'conformant'
    reflection = result('reflection', {**reflection_fact, 'observed': True, 'context': 'html_attribute'})
    assert reflection['status'] == 'suspected'
    assert 'html_attribute' in reflection['evidence']
    assert 'execution' in reflection['limitations'].lower()
    assert result('reflection', {**reflection_fact, 'observed': False})['status'] == 'conformant'


def test_wstg_references_use_contract_version():
    cors = result('cors', {'complete': True, 'observed': True, 'kind': 'wildcard', 'acao': 'wildcard', 'origin_tested': True, 'same_endpoint': True, 'credentials': False})
    reflection = result('reflection', {'complete': True, 'observed': True, 'probe_performed': True, 'parameter_authorized': True, 'marker_checked': True})
    assert 'wstg.owasp.org/v4.2/' in cors['reference']
    assert 'wstg.owasp.org/v4.2/' in reflection['reference']


def test_french_output_and_positive_protection_reason():
    args = dict(route='/secret', method='GET', date='2026-10-29')
    facts = {'hsts': {'complete': True, 'observed': True}}
    en = next(x for x in checks.evaluate_findings(facts, **args, language='en') if x['id'] == 'hsts')
    fr = next(x for x in checks.evaluate_findings(facts, **args, language='fr') if x['id'] == 'hsts')
    assert 'protection' in en['reason'].lower()
    assert 'protection' in fr['reason'].lower()
    assert 'observée' in fr['reason'].lower()
    assert en['evidence'] != fr['evidence']
    assert fr['status'] == en['status']
    assert '2026-10-29' in fr['evidence'] and 'GET' in fr['evidence']


def test_versions_never_claim_advisory_match():
    version = result('version', {'complete': True, 'observed': True})
    assert version['status'] == 'indeterminate'
    assert 'advisory' in version['limitations'].lower()


def test_redaction_and_schema_and_determinism():
    import json
    secret = 'PRIVATE_MARKER_739124'
    facts = {name: {'complete': True, 'observed': True, 'raw': secret, 'context': secret, 'kind': secret} for name in checks.CONDITIONS}
    args = dict(route='/path/'+secret+'?token='+secret, method=secret, date=secret)
    findings = checks.evaluate_findings(facts, **args)
    assert findings == checks.evaluate_findings(facts, **args)
    assert secret not in json.dumps(findings)
    fields = {'id','status','severity','reason','evidence','limitations','preconditions','recommendation','reference','method','route','date'}
    assert all(set(x) == fields and all(isinstance(v, str) for v in x.values()) for x in findings)
    assert all(x['route'] == '[redacted route]' for x in findings)
