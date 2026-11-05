import json

from app.fortress_checks import evaluate_findings


def test_cookie_positive_is_limited_and_never_copies_values():
    secret = 'COOKIE_SECRET_7642'
    facts = {'cookie_attributes': {'complete': True, 'observed': False,
                                   'cookie_count': 1, 'value': secret}}
    findings = evaluate_findings(facts, route='/private/' + secret,
                                 method='GET', date='2026-11-05')
    cookie = next(item for item in findings if item['id'] == 'cookie_attributes')
    assert cookie['status'] == 'conformant'
    assert 'applicability' in cookie['reason'].lower()
    assert 'not a certification' in cookie['reason'].lower()
    assert secret not in json.dumps(findings)
    french = evaluate_findings(facts, route='/', method='GET', date='2026-11-05', language='fr')
    cookie_fr = next(item for item in french if item['id'] == 'cookie_attributes')
    assert cookie_fr['reason'] == 'Observation limitée ; pertinence indéterminée, sans certification.'
    assert secret not in json.dumps(french)


def test_five_header_rules_distinguish_attested_valid_invalid_and_incomplete():
    names = ('hsts', 'csp', 'x_content_type_options', 'referrer_policy', 'permissions_policy')
    for observed, complete, expected in ((True, True, 'conformant'),
                                         (False, True, 'attention'),
                                         (True, False, 'indeterminate')):
        facts = {name: {'complete': complete, 'observed': observed} for name in names}
        findings = evaluate_findings(facts, route='/', method='GET', date='2026-11-05')
        assert {item['status'] for item in findings if item['id'] in names} == {expected}
