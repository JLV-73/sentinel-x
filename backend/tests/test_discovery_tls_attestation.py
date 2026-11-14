import copy
import ipaddress
import socket
import ssl
import threading
from pathlib import Path

import pytest
from app import fortress_discovery_transport as transport, fortress_discovery_policy as policy
from app.fortress_discovery_contract import valid_lab

CERTS = Path(transport.__file__).with_name('fortress_mvp_tls')


@pytest.mark.parametrize('case', ['ca', 'hostname', 'connect'])
def test_no_attestation_on_failed_tls_or_connect(monkeypatch, case):
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    port = listener.getsockname()[1]
    seen = []
    if case != 'connect':
        listener.listen(1)
        listener.settimeout(5)
        server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.load_cert_chain(str(CERTS / 'server.pem'), str(CERTS / 'server-key.pem'))
        def serve():
            try:
                conn, _ = listener.accept()
                with conn, server.wrap_socket(conn, server_side=True) as tls:
                    seen.append(tls.recv(4096))
            except (ssl.SSLError, OSError):
                pass
        thread = threading.Thread(target=serve)
        thread.start()
    else:
        listener.close()
    monkeypatch.setattr(transport, '_resolve', lambda h, p: (socket.AF_INET, '127.0.0.1'))
    monkeypatch.setattr(transport, 'public_ip', ipaddress.ip_address)
    if case == 'hostname':
        monkeypatch.setattr(ssl.SSLContext, 'load_default_certs', lambda ctx: ctx.load_verify_locations(cafile=str(CERTS / 'ca.pem')))
    name = 'wrong.invalid' if case == 'hostname' else 'standard-lab.invalid'
    try:
        response, event = transport.capture_observed(f'https://{name}:{port}/', 1024, 3)
    finally:
        if case != 'connect':
            thread.join(6)
            listener.close()
            assert not thread.is_alive()
    assert response == {}
    assert '_tls' not in event
    assert event['requests_sent'] == 0
    assert not seen
    assert event['phase'] == ('connect' if case == 'connect' else 'tls')


def test_tls_contract_rejects_bad_fields_and_preserves_old_results():
    obs = transport._evidence(200, 0, [], full=True)['evidence']
    result = policy.discover_observed('https://example.invalid', ['/'], '/', lambda *args: {
        'status': 200, 'decoded_bytes': 0, 'links': [], 'location': None, 'observations': obs})
    assert valid_lab(result)
    good = {'version': 'TLSv1.3', 'certificate_verified': True, 'hostname_verified': True, 'not_after': '2028-02-29T01:02:03Z'}
    result['pages'][0]['tls'] = good
    assert valid_lab(result)
    for change in ({'hostname_verified': False}, {'certificate_verified': 1}, {'version': 'TLSv1.1'},
                   {'not_after': '2027-02-29T01:02:03Z'}, {'extra': 'SECRET'}):
        bad = copy.deepcopy(result)
        bad['pages'][0]['tls'].update(change)
        assert not valid_lab(bad)
    bad = copy.deepcopy(result)
    bad['exclusion_reasons']['unknown'] = True
    assert not valid_lab(bad)
    del result['exclusion_reasons']
    del result['pages'][0]['tls']
    assert valid_lab(result)


def test_injected_response_cannot_claim_attested_tls():
    obs = transport._evidence(200, 0, [], full=True)['evidence']
    fake = {'version': 'TLSv1.3', 'certificate_verified': True, 'hostname_verified': True, 'not_after': None}
    result = policy.discover_observed('https://example.invalid', ['/'], '/', lambda *args: {
        'status': 200, 'decoded_bytes': 0, 'links': [], 'location': None, 'observations': obs, 'tls': fake})
    assert result['pages'] == []
