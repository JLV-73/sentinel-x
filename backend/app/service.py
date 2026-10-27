"""SQLite snapshot storage and explicit CISA ingestion."""
from contextlib import contextmanager
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import os
import sqlite3
import uuid
import time

import httpx
from .validation import validate_catalog

CANONICAL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
FALLBACK = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"


class SyncBusy(Exception):
    """Rejected requests are not actual source attempts and are not journaled."""


class Service:
    def __init__(self, db_path):
        self.db_path = Path(db_path)
        self.clock = lambda: datetime.now(timezone.utc)
        self.transport = None
        self.max_bytes = 16 * 1024 * 1024
        self.commit_timeout = 1.0  # Seconds per SQLite storage wait after writer acquisition.
        self.monotonic = time.monotonic
        self.schema_bytes = Path(__file__).with_name("kev_schema.json").read_bytes()
        self.schema_hash = hashlib.sha256(self.schema_bytes).hexdigest()

    @contextmanager
    def connect(self, timeout=5, snapshot=False):
        db = sqlite3.connect(self.db_path, timeout=timeout)
        db.row_factory = sqlite3.Row
        try:
            with db:
                # sqlite3 does not open a transaction for SELECT implicitly.
                # Compound responses must retain one committed read snapshot.
                if snapshot:
                    db.execute("BEGIN")
                yield db
        finally:
            db.close()

    def initialize(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS vulnerabilities (cve_id TEXT PRIMARY KEY, payload TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS imports (id INTEGER PRIMARY KEY, status TEXT NOT NULL, payload TEXT NOT NULL)")

    def health(self):
        with self.connect() as db:
            count = db.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
            integrity = db.execute("PRAGMA quick_check").fetchone()[0]
        return {"status": "ok", "database": integrity, "data_mode": "REAL DATA" if count else "NO DATA"}

    def last_success(self, db):
        row = db.execute("SELECT payload FROM imports WHERE status='success' ORDER BY id DESC LIMIT 1").fetchone()
        return json.loads(row[0]) if row else None

    def summary(self):
        from collections import Counter
        from datetime import timedelta
        with self.connect(snapshot=True) as db:
            items = [json.loads(row[0]) for row in db.execute("SELECT payload FROM vulnerabilities")]
            provenance = self.last_success(db)
        now = self.clock()
        lower = (now.date() - timedelta(days=29)).isoformat()
        upper = now.date().isoformat()
        vendors = Counter(item['vendorProject'] for item in items)
        months = Counter(item['dateAdded'][:7] for item in items)
        # Twelve calendar months ending in the current UTC month, zeros retained.
        period_index = now.year * 12 + now.month - 1
        periods = [f'{index // 12:04d}-{index % 12 + 1:02d}' for index in range(period_index - 11, period_index + 1)]
        return {
            'data_mode': 'REAL DATA' if items else 'NO DATA',
            'total': len(items),
            'new_last_30_days': sum(lower <= item['dateAdded'] <= upper for item in items),
            'ransomware_known': sum(item.get('knownRansomwareCampaignUse') == 'Known' for item in items),
            'vendor_count': len(vendors),
            'added_by_month': [{'period': period, 'count': months[period]} for period in periods],
            'top_vendors': [{'vendor': vendor, 'count': count} for vendor, count in sorted(vendors.items(), key=lambda pair: (-pair[1], pair[0]))[:12]],
            'latest': sorted(items, key=lambda item: (item['dateAdded'], item['cveID']), reverse=True)[:8],
            'provenance': provenance, 'as_of_utc': now.isoformat(),
        }

    def listing(self, q, vendor, ransomware, added_since, sort, page, page_size):
        # P0 catalogue fits comfortably in memory. Literal substring comparison
        # avoids SQL wildcard or injection semantics altogether.
        with self.connect() as db:
            items = [json.loads(row[0]) for row in db.execute('SELECT payload FROM vulnerabilities')]
        needle = q.strip().casefold()
        fields = ('cveID', 'vendorProject', 'product', 'vulnerabilityName', 'shortDescription')
        selected = [item for item in items
                    if (not needle or any(needle in item.get(field, '').casefold() for field in fields))
                    and (not vendor or item['vendorProject'] == vendor)
                    and (ransomware is None or item.get('knownRansomwareCampaignUse') == ransomware)
                    and (added_since is None or item['dateAdded'] >= added_since)]
        selected.sort(key=lambda item: (item['dateAdded'], item['cveID']), reverse=sort == 'desc')
        total = len(selected)
        offset = (page - 1) * page_size
        return {'items': selected[offset:offset + page_size], 'total': total,
                'page': page, 'page_size': page_size, 'pages': (total + page_size - 1) // page_size}

    def detail(self, cve_id):
        with self.connect(snapshot=True) as db:
            row = db.execute("SELECT payload FROM vulnerabilities WHERE cve_id=?", (cve_id,)).fetchone()
            return {"vulnerability": json.loads(row[0]), "provenance": self.last_success(db)} if row else None

    def save_raw(self, raw):
        digest = hashlib.sha256(raw).hexdigest()
        directory = self.db_path.parent / "source"
        directory.mkdir(parents=True, exist_ok=True)
        target = directory / (digest + ".json")
        temporary = directory / (digest + "." + uuid.uuid4().hex + ".tmp")
        try:
            with temporary.open("xb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)
        return digest

    def journal(self, db, record):
        cursor = db.execute("INSERT INTO imports(status,payload) VALUES (?,?)", (record["status"], "{}"))
        record["id"] = cursor.lastrowid
        db.execute("UPDATE imports SET payload=? WHERE id=?", (json.dumps(record), record["id"]))
        return record

    def status(self):
        with self.connect(snapshot=True) as db:
            integrity = db.execute("PRAGMA quick_check").fetchone()[0]
            count = db.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
            history = [json.loads(row[0]) for row in db.execute("SELECT payload FROM imports ORDER BY id DESC LIMIT 20")]
            success = self.last_success(db)
        return {"data_mode": "REAL DATA" if count else "NO DATA",
                "database": {"status": "ok" if integrity == "ok" else "error", "integrity": integrity, "count": count},
                "last_attempt": history[0] if history else None, "last_success": success,
                "history": history, "syncing": self.is_syncing()}

    def is_syncing(self):
        try:
            with self.connect(timeout=0) as db:
                db.execute("BEGIN IMMEDIATE")
                db.rollback()
            return False
        except sqlite3.OperationalError as error:
            if "locked" in str(error).lower():
                return True
            raise

    def download(self, client, url, deadline):
        remaining = deadline - self.monotonic()
        if remaining <= 0:
            raise ValueError("Download time budget exhausted")
        # HTTPX bounds read inactivity, not the entire request. The 45s budget
        # is cooperative: body checks can wait for an in-flight read (<=20s),
        # and transport/header processing is not a hard wall-clock deadline.
        with client.stream("GET", url, timeout=httpx.Timeout(min(20, remaining), connect=min(10, remaining))) as response:
            if self.monotonic() >= deadline:
                raise ValueError("Download time budget exhausted")
            if response.status_code != 200:
                raise ValueError("Source returned HTTP " + str(response.status_code))
            length = response.headers.get("content-length")
            if length is not None and (int(length) < 0 or int(length) > self.max_bytes):
                raise ValueError("Source exceeds size limit")
            content = bytearray()
            # No fixed chunk_size: slow incoming bytes must not accumulate in
            # HTTPX's 64 KiB buffer before the deadline can be checked.
            for chunk in response.iter_bytes():
                if self.monotonic() >= deadline:
                    raise ValueError("Download time budget exhausted")
                if len(content) + len(chunk) > self.max_bytes:
                    raise ValueError("Source exceeds size limit")
                content.extend(chunk)
            if self.monotonic() >= deadline:
                raise ValueError("Download time budget exhausted")
            return bytes(content)

    def sync(self):
        # SQLite's reserved writer lock spans the network attempt. Readers see
        # the previous committed snapshot; other workers/processes fail fast.
        with self.connect(timeout=0) as db:
            try:
                db.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as error:
                if "locked" in str(error).lower():
                    raise SyncBusy("Synchronization already in progress") from error
                raise
            success = self.last_success(db)
            if success and (self.clock() - datetime.fromisoformat(success["finished_at"])).total_seconds() < 60:
                raise SyncBusy("Source polling cooldown: wait 60 seconds after last success")
            # Acquisition stays fail-fast; an existing reader may briefly delay
            # a rollback-journal commit, which must be handled inside _sync.
            db.execute(f"PRAGMA busy_timeout={int(self.commit_timeout * 1000)}")
            return self._sync(db)

    def _sync(self, db):
        record = {"status": "failed", "started_at": self.clock().isoformat(), "finished_at": None,
                  "source_canonical": CANONICAL, "source_url": CANONICAL, "catalog_version": None,
                  "date_released": None, "record_count": None, "sha256": None,
                  "schema_sha256": self.schema_hash, "error": None, "download_attempts": []}
        try:
            document = None
            deadline = self.monotonic() + 45
            with httpx.Client(transport=self.transport, verify=True, follow_redirects=False, timeout=20, trust_env=False,
                              headers={"User-Agent": "SENTINEL-X/0.1 (local CISA KEV reader)", "Accept": "application/json"}) as client:
                for url in (CANONICAL, FALLBACK):
                    record.update(source_url=url, sha256=None)
                    attempt = {"url": url, "status": "failed", "error": None, "sha256": None}
                    record["download_attempts"].append(attempt)
                    try:
                        raw = self.download(client, url, deadline)
                        record["sha256"] = attempt["sha256"] = self.save_raw(raw)
                        document = validate_catalog(raw, json.loads(self.schema_bytes), self.clock())
                        attempt["status"] = "success"
                        break
                    except (httpx.HTTPError, ValueError, UnicodeError, RecursionError) as error:
                        attempt["error"] = str(error)[:1000]
                if document is None:
                    raise ValueError("; ".join(a["error"] or "Source failure" for a in record["download_attempts"]))
            record.update(status="success", catalog_version=document["catalogVersion"],
                          date_released=document["dateReleased"], record_count=document["count"],
                          finished_at=self.clock().isoformat())
            db.execute("DELETE FROM vulnerabilities")
            db.executemany("INSERT INTO vulnerabilities(cve_id,payload) VALUES (?,?)",
                           [(v["cveID"], json.dumps(v)) for v in document["vulnerabilities"]])
            self.journal(db, record)
            # Do not report success until the snapshot and provenance are durable.
            db.commit()
        except Exception as error:
            db.rollback()
            record.pop("id", None)
            record.update(status="failed", finished_at=self.clock().isoformat(), error=str(error)[:1000])
            try:
                db.execute("BEGIN IMMEDIATE")
                self.journal(db, record)
                db.commit()
            except sqlite3.Error as journal_error:
                db.rollback()
                record.pop("id", None)
                record["error"] += "; Failure journal not persisted: " + str(journal_error)[:500]
        return record
