"""Offline regressions; all SQLite databases live in pytest's project cache."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import timedelta

import pytest
import httpx

from app.service import Service
from test_backend import api, source, vulnerability, catalog, HEADERS, NOW


@pytest.mark.parametrize('endpoint', ['summary', 'detail', 'status'])
def test_compound_read_keeps_payload_and_provenance_in_one_snapshot(api, monkeypatch, endpoint):
    client, service = api
    old_item = vulnerability(product='Old snapshot')
    source(service, catalog(old_item))
    first = client.post('/api/sync', headers=HEADERS).json()
    # WAL on this temporary fixture allows a writer to commit at the exact
    # boundary between the response's payload/count SELECT and provenance SELECT.
    with service.connect() as db:
        assert db.execute('PRAGMA journal_mode=WAL').fetchone()[0] == 'wal'
    writer = Service(service.db_path)
    writer.clock = lambda: NOW + timedelta(seconds=61)
    source(writer, catalog(vulnerability(product='New snapshot'), vulnerability('CVE-2026-2222')))
    original_connect = service.connect
    refreshed = []

    class InterleavedConnection:
        def __init__(self, db):
            self.db = db

        def execute(self, sql, *args):
            if sql.startswith('SELECT payload FROM imports') and not refreshed:
                with ThreadPoolExecutor(max_workers=1) as pool:
                    refreshed.append(pool.submit(writer.sync).result(timeout=3))
            return self.db.execute(sql, *args)

        def __getattr__(self, name):
            return getattr(self.db, name)

    @contextmanager
    def interleaved_connect(*args, **kwargs):
        with original_connect(*args, **kwargs) as db:
            yield InterleavedConnection(db)

    monkeypatch.setattr(service, 'connect', interleaved_connect)
    paths = {'summary': '/api/summary', 'detail': '/api/vulnerabilities/' + old_item['cveID'],
             'status': '/api/sync/status'}
    response = client.get(paths[endpoint])
    assert response.status_code == 200
    result = response.json()
    assert refreshed[0]['status'] == 'success'
    if endpoint == 'summary':
        assert result['latest'] == [old_item]
        assert result['total'] == 1
        assert result['provenance'] == first
    elif endpoint == 'detail':
        assert result == {'vulnerability': old_item, 'provenance': first}
    else:
        assert result['database']['count'] == 1
        assert result['last_success'] == first
        assert result['last_attempt'] == first
        assert result['history'] == [first]
    # The next response must observe the new, fully committed snapshot.
    assert client.get('/api/summary').json()['total'] == 2
    assert client.get('/api/summary').json()['provenance'] == refreshed[0]


def test_blocked_final_commit_rolls_back_and_journals_failed_attempt(api, monkeypatch):
    import sqlite3
    import time
    from contextlib import closing

    client, service = api
    old_item = vulnerability()
    source(service, catalog(old_item))
    first = client.post('/api/sync', headers=HEADERS).json()
    service.clock = lambda: NOW + timedelta(seconds=61)
    source(service, catalog(vulnerability('CVE-2026-2222')))
    monkeypatch.setattr(service, 'commit_timeout', 0.1, raising=False)
    original_journal = service.journal
    with closing(sqlite3.connect(service.db_path)) as reader:
        assert reader.execute('PRAGMA journal_mode').fetchone()[0] == 'delete'
        reader.execute('BEGIN')
        reader.execute('SELECT * FROM vulnerabilities').fetchall()

        def release_for_failure_journal(db, record):
            if record['status'] == 'failed':
                reader.rollback()  # Storage becomes available after commit failure.
            return original_journal(db, record)

        monkeypatch.setattr(service, 'journal', release_for_failure_journal)
        started = time.monotonic()
        result = service.sync()
        elapsed = time.monotonic() - started
        assert 0.08 <= elapsed < 1
        assert result['status'] == 'failed'
        assert 'locked' in result['error'].lower()
        assert not reader.in_transaction
    status = service.status()
    assert status['last_success'] == first
    assert status['last_attempt'] == result
    assert len(status['history']) == 2
    assert service.detail(old_item['cveID']) == {'vulnerability': old_item, 'provenance': first}
    assert service.detail('CVE-2026-2222') is None


def test_slow_drip_is_checked_per_incoming_chunk_before_buffering(api):
    _, service = api
    elapsed = [0]
    received = []
    closed = []
    service.monotonic = lambda: elapsed[0]

    class SlowDrip(httpx.SyncByteStream):
        def __iter__(self):
            for _ in range(10):
                elapsed[0] += 10
                received.append(b'x')
                yield b'x'

        def close(self):
            closed.append(True)

    def handler(request):
        assert 0 < request.extensions['timeout']['read'] <= 20
        return httpx.Response(200, stream=SlowDrip())

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ValueError, match='time budget'):
            service.download(client, 'https://source.invalid/feed', 45)
    assert elapsed[0] == 50
    assert len(received) == 5
    assert closed == [True]


@pytest.mark.parametrize('phase', ['headers', 'end'])
def test_download_checks_deadline_after_headers_and_end_even_without_chunks(api, phase):
    _, service = api
    elapsed = [44]
    service.monotonic = lambda: elapsed[0]

    class EmptyStream(httpx.SyncByteStream):
        def __iter__(self):
            if phase == 'headers':
                pytest.fail('expired response must be rejected before reading the body')
            elapsed[0] = 46
            yield from ()

    def handler(request):
        assert 0 < request.extensions['timeout']['read'] <= 1
        if phase == 'headers':
            elapsed[0] = 46
        return httpx.Response(200, stream=EmptyStream())

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ValueError, match='time budget'):
            service.download(client, 'https://source.invalid/feed', 45)


@pytest.mark.parametrize('suffix', ['\n', 'trailing-garbage'])
def test_import_rejects_entire_cve_identifier_without_normalization(api, suffix):
    client, service = api
    old_item = vulnerability()
    source(service, catalog(old_item))
    first = client.post('/api/sync', headers=HEADERS).json()
    service.clock = lambda: NOW + timedelta(seconds=61)
    source(service, catalog(vulnerability(old_item['cveID'] + suffix)))
    response = client.post('/api/sync', headers=HEADERS)
    assert response.status_code == 502
    assert response.json()['detail']['status'] == 'failed'
    assert service.status()['last_success'] == first
    assert service.summary()['latest'] == [old_item]
