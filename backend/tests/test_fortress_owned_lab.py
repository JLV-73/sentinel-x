"""Offline owned loopback lab; never a production adapter or an API route."""


def test_owned_lab_returns_derived_cookie_facts():
    assert run_owned_cookie_observation() == {
        'outcome': 'ok',
        'cookies': {'count': 2, 'missing_secure': 1, 'missing_httponly': 1,
                    'missing_samesite': 1, 'indeterminate': 0},
    }


from owned_lab_helpers import run_owned_cookie_observation, OwnedHTTP, make_transport, SENTINELS
from test_fortress_tls_lab import certificates, TLSLab, client_context, transport_for, HOST, APPROVED
from app.fortress_transport import validate_scope, TransportError
from app.fortress_checks import evaluate_findings
import json
import pytest


def test_real_tls_uses_verified_ca_and_owned_loopback(certificates):
    lab = TLSLab(certificates)
    try:
        transport, url = transport_for(lab, HOST, client_context(certificates / 'ca.pem'))
        result = transport.observe('GET', url)
    finally:
        lab.finish()
    assert result['outcome'] == 'ok' and lab.record.get('handshake_complete') is True
    assert lab.record['sni'] == [HOST] and lab.record['actual_connected_peer'] == lab.address
    assert lab.address[0] == '127.0.0.1' and lab.record['simulated_reported_peer'] == APPROVED
    assert not lab.record['server_errors']


def test_request_quota_stops_before_second_socket():
    lab = OwnedHTTP()
    try:
        transport, urls, resolved, adapters = make_transport(lab, max_requests=1)
        assert transport.observe('GET', urls[0])['outcome'] == 'ok'
        assert transport.observe('GET', urls[0]) == {'outcome': 'error'}
        assert transport.blocked and transport.count == len(resolved) == len(adapters) == len(lab.requests) == 1
    finally:
        lab.close()


def test_block_response_halts_all_followups():
    lab = OwnedHTTP()
    try:
        transport, urls, resolved, adapters = make_transport(lab, paths=('/blocked', '/'))
        assert transport.observe('GET', urls[0])['outcome'] == 'blocked'
        assert transport.observe('GET', urls[1]) == {'outcome': 'error'}
        assert transport.blocked and transport.count == len(resolved) == len(adapters) == len(lab.requests) == 1
    finally:
        lab.close()


def test_out_of_scope_route_and_redirect_never_reach_network_again():
    lab = OwnedHTTP()
    try:
        transport, urls, resolved, adapters = make_transport(lab, paths=('/redirect',))
        assert transport.observe('GET', urls[0]) == {'outcome': 'error'}
        assert transport.blocked and len(resolved) == len(adapters) == len(lab.requests) == 1
        assert transport.observe('GET', urls[0]) == {'outcome': 'error'}
        direct, direct_urls, direct_resolved, direct_adapters = make_transport(lab)
        assert direct.observe('GET', direct_urls[0] + 'outside') == {'outcome': 'error'}
        assert direct.blocked and not direct_resolved and not direct_adapters and len(lab.requests) == 1
    finally:
        lab.close()


def test_private_address_rejected_without_test_adapter():
    with pytest.raises(TransportError):
        validate_scope('http://127.0.0.1/', [])


def test_derived_finding_parser_redacts_arbitrary_data():
    result = evaluate_findings({'cookie_attributes': {'complete': True, 'observed': True,
            'cookie_count': 2, 'extra': SENTINELS[0]}}, route='/lab-body-sentinel',
            method='GET', date='2026-01-01')
    finding = next(x for x in result if x['id'] == 'cookie_attributes')
    assert finding['status'] == 'attention' and finding['route'] == '[redacted route]'
    assert all(s not in json.dumps(result) for s in SENTINELS)
