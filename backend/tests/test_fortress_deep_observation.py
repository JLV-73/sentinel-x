from unittest.mock import Mock
import pytest
from test_fortress_transport import FakeSocket, URL, answer
from app.fortress_transport import SafeTransport, validate_scope, TransportError


def transport_for(payloads):
    sockets = [FakeSocket(payload) for payload in payloads]
    resolver = Mock(return_value=[answer()])
    transport = SafeTransport(validate_scope(URL, []),
                              resolver=resolver, socket_factory=Mock(side_effect=sockets),
                              scoped_probes={(URL, 'next', 'witness')})
    return transport, sockets, resolver


def response(status=200, body=b'', header=b''):
    return b'HTTP/1.1 ' + str(status).encode() + b' Result\r\n' + header + b'Content-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body


def test_attribution_requires_baseline_and_both_distinct_witnesses():
    t, sockets, resolver = transport_for([response(), response(302, header=b'Location: https://example.invalid/\r\n'), response(302, header=b'Location: https://second.invalid/\r\n')])
    result = t.observe_witness_attribution(URL, 'next')
    # Fixed sequence is not causal evidence; indeterminate must halt immediately.
    assert result == {'outcome': 'indeterminate'}
    assert resolver.call_count == 2
    assert all(call.args[0] == 'example.com' for call in resolver.call_args_list)
    assert b'example.invalid%2F' in sockets[1].sent[0]
    assert not sockets[2].sent
    assert 'invalid' not in repr(result)


@pytest.mark.parametrize('baseline', [b'', b'FORTRESS%49NERT2026 https%3A%2F%2Fexample.invalid%2F https%3A%2F%2Fsecond.invalid%2F'])
def test_scripted_static_responses_cannot_establish_causality_or_continue(baseline):
    # Responses are predetermined and do not depend on the query.
    t, sockets, resolver = transport_for([response(body=baseline), response(302, header=b'Location: https://example.invalid/\r\n'), response(302, header=b'Location: https://second.invalid/\r\n')])
    result = t.observe_witness_attribution(URL, 'next')
    assert result['outcome'] == 'indeterminate'
    assert result.get('attributed') is not True
    assert resolver.call_count == 2
    assert not sockets[2].sent
    assert t.observe_scoped_probe(URL, 'next', 'witness', witness='second')['outcome'] != 'ok'
    assert resolver.call_count == 2


def test_indeterminate_first_probe_halts_even_if_it_matches_witness():
    t, sockets, resolver = transport_for([response(), response(302, header=b'Location: https://example.invalid/\r\n'), response()])
    assert t.observe_witness_attribution(URL, 'next')['outcome'] == 'indeterminate'
    assert resolver.call_count == 2 and not sockets[2].sent


@pytest.mark.parametrize('first', [response(204), response(403), response(302, header=b'Location: /unexpected\r\n'), b'not HTTP'])
def test_odd_first_response_stops_before_third_request(first):
    t, sockets, resolver = transport_for([response(), first, response()])
    assert t.observe_witness_attribution(URL, 'next')['outcome'] == 'indeterminate'
    assert t.blocked and resolver.call_count == 2 and not sockets[2].sent
    assert t.observe_scoped_baseline(URL, 'next', 'witness')['outcome'] == 'error'
    assert resolver.call_count == 2


def test_duplicate_witness_location_is_blocked_without_following():
    t, sockets, resolver = transport_for([response(302, header=b'Location: https://second.invalid/\r\nLocation: https://second.invalid/\r\n')])
    assert t.observe_scoped_probe(URL, 'next', 'witness', witness='second')['outcome'] != 'ok'
    assert t.blocked and resolver.call_count == len(sockets[0].sent) == 1


def test_cors_redirect_indeterminate_without_following():
    t, sockets, resolver = transport_for([response(302, header=b'Location: /elsewhere\r\n')])
    t._cors_routes.add(next(iter(t.scope.routes)))
    result = t.observe_cors('GET', URL)
    assert result['outcome'] == 'indeterminate'
    assert resolver.call_count == len(sockets[0].sent) == 1


def test_scoped_probe_exposes_observed_status_not_assumed():
    t, _, _ = transport_for([response(204)])
    result = t.observe_scoped_probe(URL, 'next', 'witness')
    assert result['status'] == 204
    assert result['outcome'] == 'indeterminate'


@pytest.mark.parametrize('marker', [b'FORTRESSINERT2026', b'https://example.invalid/', b'https://second.invalid/'])
def test_preexisting_baseline_signal_prevents_attribution(marker):
    t, _, resolver = transport_for([response(body=marker)])
    assert t.observe_witness_attribution(URL, 'next') == {'outcome': 'indeterminate'}
    assert resolver.call_count == 1


@pytest.mark.parametrize('bad', [response(404), response(403), response(204), response(302, header=b'Location: https://example.invalid/\r\n')])
def test_inconclusive_baseline_prevents_probes(bad):
    t, _, resolver = transport_for([bad])
    assert t.observe_witness_attribution(URL, 'next') == {'outcome': 'indeterminate'}
    assert resolver.call_count == 1


@pytest.mark.parametrize('second', [response(), response(403), response(302, header=b'Location: https://example.invalid/\r\n'), response(302, header=b'Location: https://second.invalid/\r\nLocation: https://second.invalid/\r\n')])
def test_only_one_valid_witness_or_duplicate_location_never_attributes(second):
    t, _, resolver = transport_for([response(), response(302, header=b'Location: https://example.invalid/\r\n'), second])
    assert t.observe_witness_attribution(URL, 'next') == {'outcome': 'indeterminate'}
    # The second response is deliberately never requested after uncertainty.
    assert resolver.call_count == 2


def test_baseline_flags_both_fixed_locations_and_never_follows():
    t, _, resolver = transport_for([response(302, body=b'FORTRESSINERT2026 https://second.invalid/', header=b'Location: https://example.invalid/\r\n')])
    result = t.observe_scoped_baseline(URL, 'next', 'witness')
    assert result == {'outcome': 'indeterminate', 'status': 302, 'literal_marker_observed': True, 'literal_first_witness_observed': True, 'literal_second_witness_observed': True}
    assert resolver.call_count == 1 and 'invalid' not in repr(result)


@pytest.mark.parametrize('status', [201, 204, 404, 500])
def test_cors_non_200_is_never_ok(status):
    sock = FakeSocket(response(status, header=b'Access-Control-Allow-Origin: *\r\n'))
    resolver = Mock(return_value=[answer()])
    t = SafeTransport(validate_scope(URL, []), resolver=resolver, socket_factory=Mock(return_value=sock), cors_routes={URL})
    result = t.observe_cors('GET', URL)
    assert result['outcome'] == 'indeterminate'
    if status in (201, 204):
        assert result['status'] == status
    assert resolver.call_count == 1


def test_unapproved_baseline_and_attribution_never_resolve():
    t, _, resolver = transport_for([])
    assert t.observe_scoped_baseline(URL, 'NEXT', 'witness') == {'outcome': 'error'}
    assert t.observe_scoped_baseline(URL, 'next', 'reflection') == {'outcome': 'error'}
    assert t.observe_witness_attribution(URL, 'NEXT')['outcome'] != 'ok'
    resolver.assert_not_called()


def test_attribution_budget_exhaustion_does_not_report_negative_or_send_third():
    t, sockets, resolver = transport_for([response(), response(302, header=b'Location: https://example.invalid/\r\n')])
    t.max_requests = 2
    assert t.observe_witness_attribution(URL, 'next') == {'outcome': 'indeterminate'}
    assert resolver.call_count == 2 and sum(len(s.sent) for s in sockets) == 2


def test_baseline_transport_failure_is_redacted_and_stops_followup():
    t, _, resolver = transport_for([])
    resolver.side_effect = RuntimeError('secret-exception')
    result = t.observe_scoped_baseline(URL, 'next', 'witness')
    assert result == {'outcome': 'error'} and 'secret' not in repr(result)
    assert t.blocked
    assert t.observe_witness_attribution(URL, 'next')['outcome'] != 'ok'
    assert resolver.call_count == 1


def test_cors_sends_only_audit_target_and_controlled_headers():
    sock = FakeSocket(response())
    resolver = Mock(return_value=[answer()])
    t = SafeTransport(validate_scope(URL, []), resolver=resolver, socket_factory=Mock(return_value=sock), cors_routes={URL})
    result = t.observe_cors('OPTIONS', URL)
    assert result['status'] == 200
    assert resolver.call_count == 1 and resolver.call_args.args[0] == 'example.com'
    sent = sock.sent[0]
    assert b'OPTIONS / HTTP/1.1' in sent
    assert b'origin: https://fortress-origin.invalid\r\n' in sent
    assert b'access-control-request-method: GET\r\n' in sent
    assert b'cookie:' not in sent.lower() and b'authorization:' not in sent.lower()
