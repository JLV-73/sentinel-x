from app.fortress_transport import _header_facts
from app import fortress_service
from test_fortress_tls_lab import certificates, TLSLab, HOST, client_context, transport_for


def test_verified_tls_facts_come_from_actual_completed_handshake(certificates):
    lab = TLSLab(certificates)
    try:
        transport, url = transport_for(lab, HOST, client_context(certificates / 'ca.pem'))
        result = transport.observe_headers('GET', url)
    finally:
        lab.finish()
    assert result['tls']['certificate'] == 'verified'
    assert result['tls']['protocol'] in ('TLSv1.2', 'TLSv1.3')
    assert HOST not in repr(result)



def test_mutex_uses_global_namespace_and_fails_closed_on_denial(monkeypatch):
    class Kernel:
        name = None
        def CreateMutexW(self, security, owner, name):
            self.name = name
            return None
    kernel = Kernel()
    monkeypatch.setattr(fortress_service, '_mutex_api', lambda: kernel)
    import pytest
    with pytest.raises(fortress_service.AuditError):
        fortress_service._acquire_process_mutex()
    assert kernel.name.startswith('Global\\')


def test_service_findings_have_private_route_indices_and_finite_evidence():
    from test_fortress_service import audit, payload, Fake
    result = audit(payload(additional_urls=['https://example.invalid/second-secret']), transport_factory=Fake)
    findings = result['findings']
    assert {f['route_index'] for f in findings} == {1, 2}
    assert {f['evidence_code'] for f in findings} <= {'indeterminate', 'cookie_attributes_missing', 'header_absent'}
    assert 'second-secret' not in repr(findings)


def test_service_projects_verified_direct_tls_evidence():
    from test_fortress_service import audit, payload, Fake
    class TLSFake(Fake):
        def observe_headers(self, method, url):
            self.count += 1
            return {'outcome': 'ok', 'tls': {'certificate': 'verified', 'protocol': 'TLSv1.3'}}
    result = audit(payload(), transport_factory=TLSFake)
    finding = next(f for f in result['findings'] if f['id'] == 'https_tls')
    assert finding['status'] == 'conformant'
    assert finding['evidence_code'] == 'tls_verified'


def test_plain_http_does_not_report_missing_hsts_as_anomaly():
    from test_fortress_service import audit, payload, Fake
    class HeaderFake(Fake):
        def observe_headers(self, method, url):
            self.count += 1
            return {'outcome': 'ok', 'security_headers': {'hsts': 'absent'}}
    result = audit(payload(target='http://example.invalid/'), transport_factory=HeaderFake)
    finding = next(f for f in result['findings'] if f['id'] == 'hsts')
    assert finding['status'] == 'indeterminate'


def test_hsts_zero_max_age_is_not_recognized_protection():
    for value in ('max-age=0', 'max-age=000; includeSubDomains'):
        assert _header_facts([('Strict-Transport-Security', value)], True)['hsts'] == 'invalid'
