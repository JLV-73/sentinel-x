"""Query tracer bullets; synthetic fixtures never touch production data."""
from test_backend import api, source, vulnerability, catalog, HEADERS, NOW
import pytest


def test_catalog_search_filters_sort_and_pagination(api):
    client, service = api
    items = [vulnerability(), vulnerability('CVE-2026-2222', vendorProject='Other', product='Gadget', dateAdded='2026-10-21', knownRansomwareCampaignUse='Unknown')]
    source(service, catalog(*items))
    client.post('/api/sync', headers=HEADERS)
    response = client.get('/api/vulnerabilities?page_size=1')
    assert response.status_code == 200
    assert response.json() == {'items': [items[1]], 'total': 2, 'page': 1, 'page_size': 1, 'pages': 2}
    assert client.get('/api/vulnerabilities?page_size=1&page=2').json()['items'] == [items[0]]
    for query, expected in [('q=widget', [items[0]]), ('q=CVE-2026-2222', [items[1]]), ('vendor=Other', [items[1]]), ('ransomware=Known', [items[0]]), ('added_since=2026-10-21', [items[1]]), ('sort=asc', items), ('q=%25', []), ("q=%27%20OR%201%3D1--", [])]:
        result = client.get('/api/vulnerabilities?' + query)
        assert result.status_code == 200, result.text
        assert result.json()['items'] == expected
    assert client.get('/api/vulnerabilities?page=99').json()['items'] == []


@pytest.mark.parametrize('query', ['page=0', 'page_size=101', 'sort=invalid', 'ransomware=Yes', 'added_since=2026-02-30', 'added_since=20261020', 'q=' + 'x' * 201])
def test_catalog_rejects_invalid_inputs(api, query):
    assert api[0].get('/api/vulnerabilities?' + query).status_code == 422


def test_detail_invalid_and_unknown_identifiers(api):
    client, _ = api
    assert client.get('/api/vulnerabilities/not-a-cve').status_code == 422
    assert client.get('/api/vulnerabilities/CVE-1900-0000').status_code == 404



def test_summary_reports_real_derived_counts_and_provenance(api):
    client, service = api
    empty = client.get('/api/summary')
    assert empty.status_code == 200
    assert empty.json()['data_mode'] == 'NO DATA'
    assert empty.json()['total'] == 0
    older = vulnerability('CVE-2025-2222', vendorProject='Other', dateAdded='2025-01-02', knownRansomwareCampaignUse='Unknown')
    source(service, catalog(vulnerability(), older))
    imported = client.post('/api/sync', headers=HEADERS).json()
    response = client.get('/api/summary')
    assert response.status_code == 200
    summary = response.json()
    assert summary['total'] == 2
    assert summary['new_last_30_days'] == 1
    assert summary['ransomware_known'] == 1
    assert summary['vendor_count'] == 2
    assert summary['provenance'] == imported
    assert summary['as_of_utc'] == NOW.isoformat()
    assert next(x for x in summary['added_by_month'] if x['period'] == '2026-10')['count'] == 1
    assert summary['latest'][0]['cveID'] == 'CVE-2026-1234'
