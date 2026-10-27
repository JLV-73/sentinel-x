"""Atomicity and refresh contract against isolated synthetic source responses."""
from datetime import timedelta
import httpx
import pytest
from test_backend import api, source, vulnerability, catalog, HEADERS, NOW


def test_reimport_updates_and_removes_without_duplicates(api):
    client, service = api
    source(service, catalog(vulnerability(), vulnerability('CVE-2026-2222')))
    assert client.post('/api/sync', headers=HEADERS).status_code == 200
    service.clock = lambda: NOW + timedelta(seconds=61)
    updated = vulnerability(product='Updated product')
    source(service, catalog(updated))
    assert client.post('/api/sync', headers=HEADERS).status_code == 200
    service.clock = lambda: NOW + timedelta(seconds=122)
    assert client.post('/api/sync', headers=HEADERS).status_code == 200
    assert client.get('/api/vulnerabilities').json()['items'] == [updated]
    assert client.get('/api/vulnerabilities/CVE-2026-2222').status_code == 404
    assert len(client.get('/api/sync/status').json()['history']) == 3


@pytest.mark.parametrize('failure', ['invalid_json', 'network', 'database_write'])
def test_failed_refresh_preserves_previous_snapshot_and_success(api, failure):
    client, service = api
    item = vulnerability()
    source(service, catalog(item))
    first = client.post('/api/sync', headers=HEADERS).json()
    service.clock = lambda: NOW + timedelta(seconds=61)
    if failure == 'invalid_json':
        source(service, b'{broken')
    elif failure == 'network':
        def fail(request):
            raise httpx.ConnectError('DEMO DATA network failure')
        service.transport = httpx.MockTransport(fail)
    else:
        source(service, catalog(vulnerability('CVE-2026-3333')))
        with service.connect() as db:
            db.execute("CREATE TRIGGER fail_write BEFORE INSERT ON vulnerabilities BEGIN SELECT RAISE(ABORT, 'test write failure'); END")
    assert client.post('/api/sync', headers=HEADERS).status_code == 502
    status = client.get('/api/sync/status').json()
    assert status['last_success'] == first
    assert status['last_attempt']['status'] == 'failed'
    assert status['database']['count'] == 1
    assert client.get('/api/vulnerabilities').json()['items'] == [item]
    assert client.get('/api/vulnerabilities/' + item['cveID']).json()['provenance'] == first


def test_official_optional_fields_can_be_absent(api):
    client, service = api
    item = vulnerability()
    for key in ['knownRansomwareCampaignUse', 'notes', 'cwes', 'forensicTriage']:
        del item[key]
    source(service, catalog(item))
    assert client.post('/api/sync', headers=HEADERS).status_code == 200
    assert client.get('/api/vulnerabilities/' + item['cveID']).json()['vulnerability'] == item
    assert client.get('/api/summary').json()['ransomware_known'] == 0
