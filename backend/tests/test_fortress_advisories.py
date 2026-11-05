"""Offline tests. The source advisory is synthetic, never an official fixture."""
import importlib.util
import json
from pathlib import Path

MODULE = Path(__file__).resolve().parents[1] / 'app' / 'fortress_advisories.py'
FIXTURE = Path(__file__).parent / 'fixtures' / 'ghsa-reviewed.synthetic.json'


def test_candidate_from_attested_cache():
    assert MODULE.exists(), 'offline matcher is not implemented'
    spec = importlib.util.spec_from_file_location('fortress_advisories', MODULE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    advisory = json.loads(FIXTURE.read_text(encoding='utf-8'))[0]
    advisory['vulnerabilities'][0]['package']['ecosystem'] = 'npm'
    advisory['vulnerabilities'][0]['vulnerable_version_range'] = '>= 1.0.0 < 2.0.0'
    component = {'ecosystem': 'npm', 'package': 'synthetic-example', 'version': '1.2.3',
                 'source_verified': True, 'mapping_verified': True}
    cache = {'source': 'ghsa', 'current': True, 'provenance_verified': True,
             'complete': True, 'advisories': [advisory]}
    result = module.match_cached(component, cache)
    assert result['status'] == 'potential'
    assert result['advisories'][0]['ghsa_id'] == advisory['ghsa_id']


import copy
import pytest


@pytest.fixture
def case():
    from app.fortress_advisories import match_cached
    advisory = json.loads(FIXTURE.read_text(encoding='utf-8'))[0]
    advisory['vulnerabilities'][0]['package']['ecosystem'] = 'npm'
    advisory['vulnerabilities'][0]['vulnerable_version_range'] = '>= 1.0.0 < 2.0.0'
    component = {'ecosystem': 'npm', 'package': 'synthetic-example', 'version': '1.2.3', 'source_verified': True, 'mapping_verified': True}
    cache = {'source': 'ghsa', 'current': True, 'provenance_verified': True, 'complete': True, 'advisories': [advisory]}
    return match_cached, component, cache


@pytest.mark.parametrize('version', ['2.0.0', '0.9.9'])
def test_fixed_or_outside_range_is_not_safe_claim(case, version):
    match, component, cache = case
    component['version'] = version
    assert match(component, cache)['status'] == 'indeterminate'


@pytest.mark.parametrize('value', ['>= 1.0.0 || < 2.0.0', '^1.0.0', '1.0', '>= 1', '*', None, '>= 1.0.0 < 2.0.0-beta', '>= 1.0.0, != 1.2.3'])
def test_unsupported_ranges_are_indeterminate(case, value):
    match, component, cache = case
    cache['advisories'][0]['vulnerabilities'][0]['vulnerable_version_range'] = value
    assert match(component, cache)['status'] == 'indeterminate'


@pytest.mark.parametrize('value', [None, 'unknown', '1.2', '1.2.3-rc.1', '1.2.3+build', '01.2.3'])
def test_unknown_or_ambiguous_versions(case, value):
    match, component, cache = case
    component['version'] = value
    assert match(component, cache)['status'] == 'indeterminate'


@pytest.mark.parametrize('field,value', [('source_verified', False), ('mapping_verified', False), ('ecosystem', 'pip'), ('package', 'Synthetic-example')])
def test_component_identity_must_be_trusted_and_exact(case, field, value):
    match, component, cache = case
    component[field] = value
    assert match(component, cache)['status'] == 'indeterminate'


@pytest.mark.parametrize('field,value', [('current', False), ('provenance_verified', False), ('complete', False), ('source', 'other')])
def test_cache_must_be_attested(case, field, value):
    match, component, cache = case
    cache[field] = value
    assert match(component, cache)['status'] == 'indeterminate'


@pytest.mark.parametrize('field,value', [('withdrawn_at', '2026-10-21T00:00:00Z'), ('type', 'unreviewed'), ('github_reviewed_at', None), ('ghsa_id', 'GHSA-2345-6789-cfgh\n<script>'), ('cve_id', 'CVE-2026-1234\nsecret'), ('html_url', 'https://evil.example/secret')])
def test_untrusted_advisory_excluded(case, field, value):
    match, component, cache = case
    cache['advisories'][0][field] = value
    assert match(component, cache)['status'] == 'indeterminate'


def test_incompatible_advisory_package_and_ecosystem(case):
    match, component, cache = case
    cache['advisories'][0]['vulnerabilities'][0]['package']['name'] = 'other'
    assert match(component, cache)['status'] == 'indeterminate'
    cache['advisories'][0]['vulnerabilities'][0]['package'] = {'name': 'synthetic-example', 'ecosystem': 'pip'}
    assert match(component, cache)['status'] == 'indeterminate'


def test_no_network_or_database_access(case, monkeypatch):
    import socket
    import sqlite3
    def forbidden(*args, **kwargs):
        raise AssertionError('network or database access')
    monkeypatch.setattr(socket, 'socket', forbidden)
    monkeypatch.setattr(sqlite3, 'connect', forbidden)
    match, component, cache = case
    original = copy.deepcopy((component, cache))
    assert match(component, cache)['status'] == 'potential'
    assert (component, cache) == original


def test_output_redacts_source_strings_and_deduplicates(case):
    match, component, cache = case
    cache['advisories'][0]['description'] = 'secret-token-and-path'
    cache['advisories'].append(copy.deepcopy(cache['advisories'][0]))
    result = match(component, cache)
    assert len(result['advisories']) == 1
    assert 'secret-token-and-path' not in json.dumps(result)
    assert 'synthetic-example' not in json.dumps(result)
    assert '1.2.3' not in json.dumps(result)


def test_bounds_and_missing_withdrawal_fail_closed(case):
    match, component, cache = case
    del cache['advisories'][0]['withdrawn_at']
    assert match(component, cache)['status'] == 'indeterminate'
    cache['advisories'] *= 101
    assert match(component, cache)['reason'] == 'cache_unverified'


@pytest.mark.parametrize('expr,version,status', [('1.2.3', '1.2.3', 'potential'), ('>= 1.2.3 <= 1.2.3', '1.2.3', 'potential'), ('> 1.2.3', '1.2.3', 'indeterminate'), ('< 1.2.3', '1.2.3', 'indeterminate')])
def test_range_boundaries(case, expr, version, status):
    match, component, cache = case
    component['version'] = version
    cache['advisories'][0]['vulnerabilities'][0]['vulnerable_version_range'] = expr
    assert match(component, cache)['status'] == status


def test_unsupported_matching_range_makes_candidates_partial(case):
    match, component, cache = case
    other = copy.deepcopy(cache["advisories"][0])
    other["vulnerabilities"][0]["vulnerable_version_range"] = "^1.0.0"
    cache["advisories"].append(other)
    result = match(component, cache)
    assert result["status"] == "indeterminate"
    assert result["advisories"]


@pytest.mark.parametrize("expression, expected", [(">=1.0.0 <2.0.0", True), (">=1.0.0, <2.0.0", None), ("=  =1.2.3", None), (">=\n1.0.0", None)])
def test_strict_range_grammar(expression, expected):
    from app.fortress_advisories import _compare
    assert _compare((1, 2, 3), expression) is expected


def test_contradictory_identifier_never_becomes_candidate(case):
    match, component, cache = case
    cache["advisories"][0]["identifiers"][1]["value"] = "CVE-2026-9999"
    result = match(component, cache)
    assert result["status"] == "indeterminate"
    assert not result["advisories"]
