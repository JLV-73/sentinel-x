"""Executed live integration recipe. Reads official raw snapshots and live local API.
Use --sync to perform one real manual collection; no external endpoint override.
"""
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError
import argparse
import hashlib
import json
import sqlite3
from contextlib import closing

ROOT = Path(__file__).resolve().parents[1]
BASE = 'http://127.0.0.1:8007'


def request(path, method='GET', headers=None):
    try:
        with urlopen(Request(BASE + path, method=method, headers=headers or {}), timeout=90) as response:
            return response.status, json.load(response)
    except HTTPError as error:
        return error.code, json.loads(error.read())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--sync', action='store_true')
    parser.add_argument('--name', default='live')
    args = parser.parse_args()
    if not args.name.replace('-', '').isalnum():
        raise SystemExit('Name must be alphanumeric or hyphenated')
    report = {'run_at_utc': datetime.now(timezone.utc).isoformat(), 'checks': {}}
    status, health = request('/api/health')
    if status != 200 or health['status'] != 'ok':
        raise RuntimeError(f'Health check failed: {status}, {health}')
    report['health'] = health
    if args.sync:
        status, synced = request('/api/sync', 'POST', {'Origin': 'http://127.0.0.1:5177', 'X-Sentinel-Request': 'sync'})
        report['sync'] = synced
        if status != 200 or synced['status'] != 'success':
            raise RuntimeError(f'Sync failed: {status}, {synced}')
    status, system = request('/api/sync/status')
    if status != 200 or not system['last_success']:
        raise RuntimeError(f'Sync status check failed: {status}, {system}')
    report['system'] = system
    origin_check = request('/api/sync', 'POST', {'Origin': 'https://third-party.invalid', 'X-Sentinel-Request': 'sync'})[0]
    no_origin = request('/api/sync', 'POST')[0]
    if origin_check != 403 or no_origin != 403:
        raise RuntimeError(f'Origin rejection failed: {origin_check}, {no_origin}')
    report['checks']['foreign_and_missing_origin_rejected'] = True
    provenance = system['last_success']
    snapshot = ROOT / 'data/source' / (provenance['sha256'] + '.json')
    raw_bytes = snapshot.read_bytes()
    if hashlib.sha256(raw_bytes).hexdigest() != provenance['sha256']:
        raise RuntimeError('Raw snapshot SHA-256 mismatch')
    raw = json.loads(raw_bytes)
    if not raw['count'] == len(raw['vulnerabilities']) == provenance['record_count']:
        raise RuntimeError('Raw snapshot record count mismatch')
    if len({row['cveID'] for row in raw['vulnerabilities']}) != raw['count']:
        raise RuntimeError('Raw snapshot CVE identifiers are not unique')
    report['checks']['raw_hash_count_uniqueness'] = True
    status, summary = request('/api/summary')
    if status != 200:
        raise RuntimeError(f'Summary request failed: HTTP {status}')
    if summary['total'] != raw['count'] or summary['data_mode'] != 'REAL DATA':
        raise RuntimeError('Summary does not match raw snapshot')
    if sum(row['count'] for row in summary['added_by_month']) > raw['count']:
        raise RuntimeError('Summary monthly count exceeds raw snapshot count')
    report['summary'] = summary
    by_cve = {row['cveID']: row for row in raw['vulnerabilities']}
    collected = []
    page = 1
    while True:
        code, listing = request(f'/api/vulnerabilities?page={page}&page_size=100')
        if code != 200 or listing['total'] != raw['count']:
            raise RuntimeError(f'Listing check failed: {code}, {listing}')
        for row in listing['items']:
            if row != by_cve[row['cveID']]:
                raise RuntimeError(f'Listing record differs from raw snapshot: {row["cveID"]}')
        collected.extend(listing['items'])
        if page >= listing['pages']:
            break
        page += 1
    if not len(collected) == raw['count'] == len({row['cveID'] for row in collected}):
        raise RuntimeError('Collected record count or uniqueness mismatch')
    report['checks']['all_api_records_equal_official_raw'] = len(collected)
    sample = collected[0]
    code, detail = request('/api/vulnerabilities/' + sample['cveID'])
    if code != 200 or detail['vulnerability'] != by_cve[sample['cveID']]:
        raise RuntimeError('Detail does not match raw snapshot')
    code, listing = request('/api/vulnerabilities?q=' + sample['cveID'])
    if code != 200 or not any(row['cveID'] == sample['cveID'] for row in listing['items']):
        raise RuntimeError('Search did not return the expected CVE')
    if request('/api/vulnerabilities/CVE-1900-0000')[0] != 404:
        raise RuntimeError('Missing CVE was not rejected with HTTP 404')
    if request('/api/vulnerabilities/not-a-cve')[0] != 422:
        raise RuntimeError('Invalid CVE was not rejected with HTTP 422')
    if request('/api/vulnerabilities?page=0')[0] != 422:
        raise RuntimeError('Invalid page was not rejected with HTTP 422')
    if request('/api/vulnerabilities?page_size=101')[0] != 422:
        raise RuntimeError('Invalid page size was not rejected with HTTP 422')
    report['checks']['detail_search_missing_invalid_pagination'] = True
    report['verified_sample'] = sample
    with closing(sqlite3.connect((ROOT / 'data/sentinel.db').as_uri() + '?mode=ro', uri=True)) as db:
        integrity = db.execute('PRAGMA integrity_check').fetchone()[0]
        if integrity != 'ok':
            raise RuntimeError(f'SQLite integrity check failed: {integrity}')
        report['sqlite_integrity'] = integrity
    report['result'] = 'PASS'
    destination = ROOT / 'docs/evidence' / (args.name + '.json')
    destination.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({'result': report['result'], 'records_verified': len(collected), 'catalog_version': raw['catalogVersion'], 'source_url': provenance['source_url'], 'sha256': provenance['sha256'], 'sample': sample['cveID'], 'evidence': str(destination)}, indent=2))


if __name__ == '__main__':
    main()
