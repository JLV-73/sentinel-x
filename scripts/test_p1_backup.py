"""P1 additive backup regression; synthetic raw replies never touch real data."""
from contextlib import closing
from pathlib import Path
import hashlib
import json
import sqlite3
import tempfile
import unittest
import zipfile
from backup import backup, ROOT


class IntelligenceBackupTests(unittest.TestCase):
    def test_backup_keeps_nested_nvd_epss_raw_provenance(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.cache') as temporary:
            root = Path(temporary)
            (root / 'data').mkdir()
            with closing(sqlite3.connect(root / 'data/sentinel.db')) as database:
                with database:
                    database.execute('CREATE TABLE sample (cve TEXT)')
                    database.execute('INSERT INTO sample VALUES (?)', ('CVE-2021-44228',))
            replies = {}
            for source in ('nvd', 'epss'):
                raw = json.dumps({'source': source, 'mode': 'DEMO DATA test only'}).encode()
                relative = 'intelligence_raw/' + source + '/' + hashlib.sha256(raw).hexdigest() + '.json'
                path = root / 'data' / relative
                path.parent.mkdir(parents=True)
                path.write_bytes(raw)
                replies[relative] = raw
            archive = backup(root)
            with zipfile.ZipFile(archive) as zipped:
                manifest = json.loads(zipped.read('manifest.json'))
                for name, raw in replies.items():
                    self.assertIn(name, zipped.namelist())
                    self.assertEqual(zipped.read(name), raw)
                    self.assertEqual(manifest['files'][name], hashlib.sha256(raw).hexdigest())
                    self.assertEqual((root / 'data' / name).read_bytes(), raw)


if __name__ == '__main__':
    unittest.main()
