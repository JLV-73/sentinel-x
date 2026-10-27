"""Isolated tests for local operation scripts (no network)."""
import importlib.util
from pathlib import Path
from contextlib import closing, redirect_stdout
import hashlib
import io
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    path = ROOT / 'scripts' / (name + '.py')
    if not path.exists():
        raise AssertionError(f'Missing operational script: {path.name}')
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_verify_fixture(root, fault=''):
    """Run the real verifier with local files and a fake HTTP boundary."""
    root = Path(root)
    source = root / 'data/source'
    source.mkdir(parents=True)
    (root / 'docs/evidence').mkdir(parents=True)
    sample = {'cveID': 'CVE-2026-0001'}
    records = [sample, sample] if fault == 'raw_duplicate' else [sample]
    raw = {'catalogVersion': 'fixture', 'count': len(records), 'vulnerabilities': records}
    if fault == 'raw_count':
        raw['count'] += 1
    raw_bytes = json.dumps(raw).encode()
    digest = hashlib.sha256(raw_bytes).hexdigest()
    (source / (digest + '.json')).write_bytes(raw_bytes + (b' ' if fault == 'raw_hash' else b''))
    with closing(sqlite3.connect(root / 'data/sentinel.db')) as db:
        db.execute('CREATE TABLE fixture (value TEXT)')
        db.commit()
    provenance = {'sha256': digest, 'record_count': len(records), 'source_url': 'fixture://no-network'}
    summary = {'total': raw['count'], 'data_mode': 'REAL DATA', 'added_by_month': [{'count': len(records)}]}
    if fault == 'summary_content':
        summary['data_mode'] = 'DEMO DATA'
    if fault == 'summary_months':
        summary['added_by_month'][0]['count'] = len(records) + 1
    calls = []

    def fake_request(path, method='GET', headers=None):
        calls.append(path)
        if path == '/api/health':
            return (500 if fault == 'health_status' else 200), {'status': 'bad' if fault == 'health_content' else 'ok'}
        if path == '/api/sync':
            if headers and headers.get('Origin') == 'http://127.0.0.1:5177':
                return (500 if fault == 'sync_status' else 200), {'status': 'bad' if fault == 'sync_content' else 'success'}
            return (200 if fault == 'origin' else 403), {}
        if path == '/api/sync/status':
            return (500 if fault == 'system_status' else 200), {'last_success': provenance}
        if path == '/api/summary':
            return (500 if fault == 'summary_status' else 200), summary
        if path == '/api/vulnerabilities?page=1&page_size=100':
            items = [{'cveID': sample['cveID'], 'unexpected': True}] if fault == 'listing_row' else records
            if fault == 'listing_count':
                items = records * 2
            return (500 if fault == 'listing_status' else 200), {'total': raw['count'] + (fault == 'listing_total'), 'items': items, 'pages': 1}
        if path == '/api/vulnerabilities/' + sample['cveID']:
            return 200, {'vulnerability': {} if fault == 'detail' else sample}
        if path == '/api/vulnerabilities?q=' + sample['cveID']:
            return 200, {'items': [] if fault == 'search' else [sample]}
        invalid = {
            '/api/vulnerabilities/CVE-1900-0000': ('missing_cve', 404),
            '/api/vulnerabilities/not-a-cve': ('invalid_cve', 422),
            '/api/vulnerabilities?page=0': ('invalid_page', 422),
            '/api/vulnerabilities?page_size=101': ('invalid_page_size', 422),
        }
        if path in invalid:
            name, status = invalid[path]
            return (200 if fault == name else status), {}
        raise AssertionError('Unexpected HTTP request: ' + path)

    verifier = load('verify_live')
    error = None
    with mock.patch.object(verifier, 'ROOT', root), mock.patch.object(verifier, 'request', fake_request), mock.patch.object(sys, 'argv', ['verify_live.py', '--sync', '--name', 'fixture']), redirect_stdout(io.StringIO()):
        try:
            verifier.main()
        except Exception as caught:
            error = type(caught).__name__ + ': ' + str(caught)
    evidence = root / 'docs/evidence/fixture.json'
    return {'error': error, 'calls': calls, 'report': json.loads(evidence.read_text()) if evidence.exists() else None}


class VerifyLiveTests(unittest.TestCase):
    def run_fixture(self, fault='', optimized=True):
        with tempfile.TemporaryDirectory(dir=ROOT / '.cache') as temp:
            environment = os.environ.copy()
            environment.update(TMP=str(ROOT / '.cache'), TEMP=str(ROOT / '.cache'), PYTHONPYCACHEPREFIX=str(ROOT / '.cache/pycache'))
            command = [sys.executable] + (['-O'] if optimized else []) + [
                '-c',
                'from scripts.test_operations import run_verify_fixture; import json, sys; print(json.dumps(run_verify_fixture(sys.argv[1], sys.argv[2])))',
                temp, fault,
            ]
            result = subprocess.run(command, cwd=ROOT, env=environment, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return json.loads(result.stdout)

    def test_optimized_verification_rejects_failed_checks(self):
        for fault in (
            'health_status', 'health_content', 'sync_status', 'sync_content', 'system_status',
            'origin', 'raw_hash', 'raw_count', 'raw_duplicate', 'summary_content', 'summary_months',
            'listing_status', 'listing_total', 'listing_row', 'listing_count', 'detail', 'search',
            'missing_cve', 'invalid_cve', 'invalid_page', 'invalid_page_size',
        ):
            with self.subTest(fault=fault):
                result = self.run_fixture(fault)
                self.assertIsNotNone(result['error'], 'Invalid data was accepted as PASS')
                self.assertIsNone(result['report'], 'Failure must not produce PASS evidence')

    def test_summary_http_failure_is_rejected_even_with_matching_json(self):
        for optimized in (False, True):
            with self.subTest(optimized=optimized):
                result = self.run_fixture('summary_status', optimized=optimized)
                self.assertIsNotNone(result['error'], 'HTTP 500 summary was accepted as PASS')
                self.assertIn('500', result['error'])
                self.assertIsNone(result['report'])

    def test_verification_executes_all_requests(self):
        expected = [
            '/api/health', '/api/sync', '/api/sync/status', '/api/sync', '/api/sync',
            '/api/summary', '/api/vulnerabilities?page=1&page_size=100',
            '/api/vulnerabilities/CVE-2026-0001', '/api/vulnerabilities?q=CVE-2026-0001',
            '/api/vulnerabilities/CVE-1900-0000', '/api/vulnerabilities/not-a-cve',
            '/api/vulnerabilities?page=0', '/api/vulnerabilities?page_size=101',
        ]
        for optimized in (False, True):
            with self.subTest(optimized=optimized):
                result = self.run_fixture(optimized=optimized)
                self.assertIsNone(result['error'])
                self.assertEqual(result['calls'], expected)
                self.assertEqual(result['report']['result'], 'PASS')


class LauncherTests(unittest.TestCase):
    def test_commands_only_bind_loopback_and_use_project_python(self):
        commands = load('dev').build_commands(ROOT, 'node.exe')
        self.assertEqual(set(commands), {'backend', 'frontend'})
        for args in commands.values():
            self.assertIn('127.0.0.1', args)
            self.assertNotIn('0.0.0.0', args)
        self.assertEqual(Path(commands['backend'][0]), ROOT / '.venv' / 'Scripts' / 'python.exe')
        self.assertIn('8007', commands['backend'])
        self.assertIn('-I', commands['backend'], 'Backend must ignore inherited PYTHONPATH/PYTHONHOME')
        self.assertIn('5177', commands['frontend'])
        self.assertIn('--strictPort', commands['frontend'])


class BackupTests(unittest.TestCase):
    def test_backup_failure_does_not_publish_or_leave_staging(self):
        import zipfile
        for fault in ('write', 'crc', 'membership', 'manifest', 'content'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(dir=ROOT / '.cache') as temp:
                root = Path(temp)
                source = root / 'data/source'
                source.mkdir(parents=True)
                snapshot = source / 'fixture.json'
                raw = b'{"test":"DEMO DATA only"}'
                snapshot.write_bytes(raw)
                database = root / 'data/sentinel.db'
                with closing(sqlite3.connect(database)) as db:
                    db.execute('CREATE TABLE fixture (value TEXT)')
                    db.execute('INSERT INTO fixture VALUES (?)', ('keep me',))
                    db.commit()
                original = database.read_bytes()
                destination = root / 'data/backups'
                destination.mkdir()
                previous = destination / 'previous.zip'
                previous.write_bytes(b'previous backup must survive')

                class FaultyZipFile(zipfile.ZipFile):
                    def write(self, filename, arcname=None, **kwargs):
                        if arcname == 'source/fixture.json':
                            if fault == 'membership':
                                return
                            if fault in ('content', 'crc'):
                                self.writestr(arcname, b'changed' if fault == 'content' else raw, compress_type=zipfile.ZIP_STORED)
                                return
                        super().write(filename, arcname, **kwargs)
                        if fault == 'write':
                            raise OSError('injected archive write failure')

                    def writestr(self, name, contents, **kwargs):
                        if fault == 'manifest' and name == 'manifest.json':
                            changed = json.loads(contents)
                            changed['created_at_utc'] = 'tampered'
                            contents = json.dumps(changed)
                        return super().writestr(name, contents, **kwargs)

                    def close(self):
                        corrupt = fault == 'crc' and self.mode == 'x' and self.fp is not None
                        if corrupt:
                            info = self.getinfo('source/fixture.json')
                            offset = info.header_offset + 30 + len(info.filename.encode()) + len(info.extra)
                        super().close()
                        if corrupt:
                            with open(self.filename, 'r+b') as handle:
                                handle.seek(offset)
                                handle.write(b'X')

                module = load('backup')
                with mock.patch.object(module.zipfile, 'ZipFile', FaultyZipFile):
                    with self.assertRaises((OSError, RuntimeError, zipfile.BadZipFile)):
                        module.backup(root)
                self.assertEqual(list(destination.iterdir()), [previous], 'Failed backup left a final or staging artifact')
                self.assertEqual(previous.read_bytes(), b'previous backup must survive')
                self.assertEqual(database.read_bytes(), original)
                self.assertEqual(snapshot.read_bytes(), raw)
                with closing(sqlite3.connect(database)) as db:
                    self.assertEqual(db.execute('SELECT value FROM fixture').fetchone(), ('keep me',))

    def test_backup_is_published_only_after_validation(self):
        import zipfile
        with tempfile.TemporaryDirectory(dir=ROOT / '.cache') as temp:
            root = Path(temp)
            (root / 'data').mkdir()
            with closing(sqlite3.connect(root / 'data/sentinel.db')) as db:
                db.execute('CREATE TABLE fixture (value TEXT)')
                db.commit()
            destination = root / 'data/backups'
            testzip = zipfile.ZipFile.testzip
            validated = []

            def observe_validation(zipped):
                self.assertEqual(list(destination.glob('*.zip')), [], 'Final ZIP was visible before validation')
                staging = Path(zipped.filename)
                self.assertEqual(staging.suffix, '.partial')
                self.assertTrue(staging.is_relative_to(destination))
                validated.append(staging)
                return testzip(zipped)

            module = load('backup')
            with mock.patch.object(module.zipfile.ZipFile, 'testzip', observe_validation):
                archive = module.backup(root)
            self.assertEqual(len(validated), 1)
            self.assertEqual(list(destination.iterdir()), [archive])
            self.assertFalse(validated[0].exists())

    def test_online_backup_includes_committed_wal_without_changing_source(self):
        import zipfile
        with tempfile.TemporaryDirectory(dir=ROOT / '.cache') as temp:
            root = Path(temp)
            (root / 'data').mkdir()
            database = root / 'data/sentinel.db'
            with closing(sqlite3.connect(database)) as writer:
                self.assertEqual(writer.execute('PRAGMA journal_mode=WAL').fetchone()[0], 'wal')
                writer.execute('CREATE TABLE fixture (value TEXT)')
                writer.commit()
                writer.execute('PRAGMA wal_checkpoint(TRUNCATE)')
                writer.execute('INSERT INTO fixture VALUES (?)', ('committed in WAL',))
                writer.commit()
                with closing(sqlite3.connect(database.as_uri() + '?mode=ro&immutable=1', uri=True)) as main_only:
                    self.assertEqual(main_only.execute('SELECT count(*) FROM fixture').fetchone()[0], 0)
                wal = database.with_name(database.name + '-wal')
                original_database, original_wal = database.read_bytes(), wal.read_bytes()
                self.assertGreater(len(original_wal), 0)
                module = load('backup')
                archive = module.backup(root)
                archive_bytes = archive.read_bytes()
                second = module.backup(root)
                self.assertNotEqual(archive, second)
                self.assertEqual(archive.read_bytes(), archive_bytes)
                self.assertEqual(database.read_bytes(), original_database)
                self.assertEqual(wal.read_bytes(), original_wal)
                self.assertEqual(writer.execute('SELECT value FROM fixture').fetchone(), ('committed in WAL',))
                with zipfile.ZipFile(archive) as zipped:
                    zipped.extract('sentinel.db', root / 'verify')
                with closing(sqlite3.connect(root / 'verify/sentinel.db')) as restored:
                    self.assertEqual(restored.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
                    self.assertEqual(restored.execute('SELECT value FROM fixture').fetchone(), ('committed in WAL',))

    def test_backup_is_consistent_and_includes_raw_source(self):
        import tempfile
        import sqlite3
        import zipfile
        import hashlib
        with tempfile.TemporaryDirectory(dir=ROOT / '.cache') as temp:
            root = Path(temp)
            source = root / 'data/source'
            source.mkdir(parents=True)
            raw = b'{"test":"DEMO DATA only"}'
            snapshot = source / (hashlib.sha256(raw).hexdigest() + '.json')
            snapshot.write_bytes(raw)
            with closing(sqlite3.connect(root / 'data/sentinel.db')) as db:
                db.execute('CREATE TABLE sample (cve TEXT)')
                db.execute('INSERT INTO sample VALUES (?)', ('CVE-2026-0001',))
                db.commit()
            archive = load('backup').backup(root)
            self.assertTrue(archive.is_relative_to(root / 'data/backups'))
            self.assertTrue(snapshot.exists())
            with zipfile.ZipFile(archive) as zipped:
                self.assertIn('sentinel.db', zipped.namelist())
                self.assertEqual(zipped.read('source/' + snapshot.name), raw)
                zipped.extract('sentinel.db', root / 'verify')
            with closing(sqlite3.connect(root / 'verify/sentinel.db')) as db:
                self.assertEqual(db.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
                self.assertEqual(db.execute('SELECT count(*) FROM sample').fetchone()[0], 1)


if __name__ == '__main__':
    unittest.main()
