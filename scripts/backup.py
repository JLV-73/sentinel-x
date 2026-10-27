"""On-demand project-only backup; uses SQLite online backup, never copies a live DB file."""
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import sqlite3
import tempfile
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def backup(root=ROOT):
    root = Path(root).resolve()
    data = root / 'data'
    database = data / 'sentinel.db'
    if not database.is_file():
        raise SystemExit('Pas de base SENTINEL X a sauvegarder.')
    destination = data / 'backups'
    destination.mkdir(parents=True, exist_ok=True)
    archive = destination / ('sentinel-x-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8] + '.zip')
    with tempfile.TemporaryDirectory(dir=destination) as temporary:
        snapshot = Path(temporary) / 'sentinel.db'
        partial = Path(temporary) / (archive.name + '.partial')
        with closing(sqlite3.connect(database.as_uri() + '?mode=ro', uri=True, timeout=10)) as source, closing(sqlite3.connect(snapshot)) as target:
            source.backup(target)
            if target.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                raise RuntimeError('Sauvegarde interrompue : integrite SQLite incorrecte.')
        files = [snapshot] + sorted((data / 'source').glob('*.json'))
        manifest = {'created_at_utc': datetime.now(timezone.utc).isoformat(), 'files': {}}
        with zipfile.ZipFile(partial, 'x', compression=zipfile.ZIP_DEFLATED) as zipped:
            for path in files:
                relative = 'sentinel.db' if path == snapshot else 'source/' + path.name
                manifest['files'][relative] = hashlib.sha256(path.read_bytes()).hexdigest()
                zipped.write(path, relative)
            zipped.writestr('manifest.json', json.dumps(manifest, indent=2))
        with zipfile.ZipFile(partial) as zipped:
            if zipped.testzip() is not None:
                raise RuntimeError('Archive ZIP incorrecte, ne pas utiliser cette sauvegarde.')
            expected = set(manifest['files']) | {'manifest.json'}
            names = zipped.namelist()
            if set(names) != expected or len(names) != len(expected):
                raise RuntimeError('Archive ZIP incomplete ou contenant des fichiers inattendus.')
            if json.loads(zipped.read('manifest.json')) != manifest:
                raise RuntimeError('Manifeste de sauvegarde incorrect.')
            for relative, digest in manifest['files'].items():
                if hashlib.sha256(zipped.read(relative)).hexdigest() != digest:
                    raise RuntimeError(f'Empreinte de sauvegarde incorrecte : {relative}')
        partial.rename(archive)
    return archive


if __name__ == '__main__':
    print(backup())
