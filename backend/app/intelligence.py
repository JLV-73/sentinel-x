"""Additive intelligence storage. GETs read SQLite only; collection is manual.

Control leases and rate reservations are short SQLite transactions, never held
across network I/O. A crashed worker's lease expires after 120 seconds. Request
start reservations/cooldowns survive restarts. No background retry or scheduler.
"""
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
import hashlib
import json
import os
import sqlite3
import time
import uuid

from .sourceclients import ENDPOINTS, SourceClient, cve_id, parse_nvd, parse_epss, pack_epss


class IntelligenceBusy(Exception):
    pass


class IntelligenceFailure(Exception):
    def __init__(self, attempt):
        self.attempt = attempt
        super().__init__(attempt["error"] or "Intelligence collection failed")


class IntelligenceService:
    def __init__(self, cisa):
        self.cisa = cisa
        self.client = SourceClient()
        self.sleep = time.sleep
        self.commit_timeout = 1

    def now(self):
        return self.cisa.clock().astimezone(timezone.utc)

    def initialize(self):
        with self.cisa.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS intelligence_attempts (
                    id INTEGER PRIMARY KEY, source TEXT NOT NULL, status TEXT NOT NULL, payload TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS intelligence_source_history ON intelligence_attempts(source,id);
                CREATE TABLE IF NOT EXISTS intelligence_targets (
                    attempt_id INTEGER NOT NULL, source TEXT NOT NULL, cve_id TEXT NOT NULL, succeeded INTEGER NOT NULL,
                    PRIMARY KEY(attempt_id,cve_id));
                CREATE INDEX IF NOT EXISTS intelligence_target_history ON intelligence_targets(source,cve_id,attempt_id);
                CREATE TABLE IF NOT EXISTS intelligence_cache (
                    source TEXT NOT NULL, cve_id TEXT NOT NULL, data TEXT, provenance TEXT NOT NULL,
                    collected_at TEXT NOT NULL, source_date TEXT, success_id INTEGER NOT NULL,
                    PRIMARY KEY(source,cve_id));
                CREATE TABLE IF NOT EXISTS intelligence_control (
                    source TEXT PRIMARY KEY, token TEXT, lease_until REAL NOT NULL DEFAULT 0,
                    next_request REAL NOT NULL DEFAULT 0);
            """)
            for source in ENDPOINTS:
                db.execute("INSERT OR IGNORE INTO intelligence_control(source) VALUES (?)", (source,))

    def _local_ids(self, db, ids):
        for value in ids:
            cve_id(value)
            if not db.execute("SELECT 1 FROM vulnerabilities WHERE cve_id=?", (value,)).fetchone():
                raise KeyError(value)

    def get(self, value):
        return self.get_many([value])["items"][value]

    def get_many(self, ids):
        with self.cisa.connect(snapshot=True) as db:
            self._local_ids(db, ids)
            return {"items": {value: {"cve_id": value, **{source: self._view(db, source, value) for source in ENDPOINTS}} for value in ids}}

    def _attempt(self, db, attempt_id):
        row = db.execute("SELECT payload FROM intelligence_attempts WHERE id=?", (attempt_id,)).fetchone() if attempt_id else None
        return json.loads(row[0]) if row else None

    def _view(self, db, source, value):
        cached = db.execute("SELECT * FROM intelligence_cache WHERE source=? AND cve_id=?", (source, value)).fetchone()
        target = db.execute("SELECT attempt_id,succeeded FROM intelligence_targets WHERE source=? AND cve_id=? ORDER BY attempt_id DESC LIMIT 1", (source, value)).fetchone()
        data = json.loads(cached["data"]) if cached and cached["data"] is not None else None
        stale = bool(cached and (self.now() - datetime.fromisoformat(cached["collected_at"]) >= timedelta(hours=168 if source == "nvd" else 24)
                     or (source == "epss" and data and (self.now().date() - datetime.fromisoformat(data["date"]).date()).days > 2)))
        failed = bool(target and not target["succeeded"])
        state = ("unavailable" if failed else "not_requested" if cached is None else "stale" if stale
                 else "absent" if data is None else "available")
        return {"state": state, "stale": stale, "retained_after_error": bool(failed and cached),
                "collected_at": cached["collected_at"] if cached else None,
                "source_date": cached["source_date"] if cached else None, "data": data,
                "provenance": json.loads(cached["provenance"]) if cached else None,
                "last_attempt": self._attempt(db, target["attempt_id"]) if target else None,
                "last_success": self._attempt(db, cached["success_id"]) if cached else None}

    def _coverage(self, db, source, ids):
        result = dict.fromkeys(("available", "with_scores", "absent", "unavailable", "stale", "not_requested"), 0)
        for value in ids:
            view = self._view(db, source, value)
            result[view["state"]] += 1
            if view["data"] is not None and (source == "epss" or view["data"]["cvss"]):
                result["with_scores"] += 1
        return result

    def summary(self):
        with self.cisa.connect(snapshot=True) as db:
            ids = [row[0] for row in db.execute("SELECT cve_id FROM vulnerabilities")]
            return {"catalog_total": len(ids), **{source: self._coverage(db, source, ids) for source in ENDPOINTS}}

    def status(self):
        with self.cisa.connect(snapshot=True) as db:
            ids = [row[0] for row in db.execute("SELECT cve_id FROM vulnerabilities")]
            result = {}
            for source, endpoint in ENDPOINTS.items():
                history = [json.loads(row[0]) for row in db.execute("SELECT payload FROM intelligence_attempts WHERE source=? ORDER BY id DESC LIMIT 20", (source,))]
                success = db.execute("SELECT payload FROM intelligence_attempts WHERE source=? AND status IN ('success','partial') ORDER BY id DESC LIMIT 1", (source,)).fetchone()
                control = db.execute("SELECT token,lease_until FROM intelligence_control WHERE source=?", (source,)).fetchone()
                result[source] = {"source": source, **self._coverage(db, source, ids), "last_attempt": history[0] if history else None,
                                  "last_success": json.loads(success[0]) if success else None, "history": history,
                                  "freshness_hours": 168 if source == "nvd" else 24,
                                  "busy": bool(control["token"] and control["lease_until"] > self.now().timestamp()), "endpoint": endpoint}
            return result

    def _acquire(self, source):
        token, now = uuid.uuid4().hex, self.now().timestamp()
        try:
            with self.cisa.connect(timeout=0) as db:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute("SELECT * FROM intelligence_control WHERE source=?", (source,)).fetchone()
                if row["token"] and row["lease_until"] > now:
                    raise IntelligenceBusy("Source collection already in progress")
                if row["next_request"] > now:
                    try:
                        until = datetime.fromtimestamp(row["next_request"], timezone.utc).isoformat()
                    except (ValueError, OverflowError, OSError):
                        until = "deferred manual retry (source delay exceeds supported timestamp range)"
                    raise IntelligenceBusy("Source cooldown until " + until)
                db.execute("UPDATE intelligence_control SET token=?,lease_until=? WHERE source=?", (token, now + 120, source))
        except sqlite3.OperationalError as error:
            if "locked" in str(error).lower():
                raise IntelligenceBusy("Database busy; collection not started") from error
            raise
        return token

    def _reserve_request(self, source, token):
        with self.cisa.connect(timeout=self.commit_timeout) as db:
            db.execute("BEGIN IMMEDIATE")
            row = self._owned_lease(db, source, token)
            now = self.now().timestamp()
            if row["next_request"] > now:
                raise IntelligenceBusy("Source request cooldown")
            db.execute("UPDATE intelligence_control SET next_request=?,lease_until=? WHERE source=? AND token=?",
                       (now + (7 if source == "nvd" else 1), now + 120, source, token))

    def _owned_lease(self, db, source, token):
        # Called under BEGIN IMMEDIATE: takeover cannot race the ensuing writes.
        row = db.execute("SELECT * FROM intelligence_control WHERE source=?", (source,)).fetchone()
        if row["token"] != token or row["lease_until"] <= self.now().timestamp():
            raise IntelligenceBusy("Source lease superseded or expired; collection not committed")
        return row

    def _release(self, source, token):
        try:
            with self.cisa.connect(timeout=self.commit_timeout) as db:
                db.execute("UPDATE intelligence_control SET token=NULL,lease_until=0 WHERE source=? AND token=?", (source, token))
        except sqlite3.OperationalError as error:
            code = getattr(error, "sqlite_errorcode", 0)
            if code & 0xff not in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED):
                raise
            # Response-only warning: another writer may prevent any journal update.
            # Never replace a durable success or the original structured failure.
            return {"cleanup_deferred": True,
                    "cleanup_warning": "Source lease cleanup deferred by SQLite contention; lease will expire without background retry."}
        return {}

    def _defer(self, source, header):
        delay = 60.0
        if header is not None:
            try:
                delay = float(header) if header.isascii() and header.isdigit() else (parsedate_to_datetime(header).astimezone(timezone.utc) - self.now()).total_seconds()
            except (ValueError, OverflowError, TypeError):
                pass
        # Never clamp a long official Retry-After and then immediately retry.
        until = self.now().timestamp() + max(0, delay)
        with self.cisa.connect(timeout=self.commit_timeout) as db:
            db.execute("UPDATE intelligence_control SET next_request=MAX(next_request,?) WHERE source=?", (until, source))

    def _raw(self, source, fetched):
        digest = hashlib.sha256(fetched.raw).hexdigest()
        directory = self.cisa.db_path.parent / "intelligence_raw" / source
        directory.mkdir(parents=True, exist_ok=True)
        target = directory / (digest + ".json")
        temporary = directory / (digest + "." + uuid.uuid4().hex + ".tmp")
        try:
            with temporary.open("xb") as stream:
                stream.write(fetched.raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)
        return {"source": source, "url": fetched.url, "sha256": digest, "collected_at": self.now().isoformat(),
                "raw_file": target.relative_to(self.cisa.db_path.parent).as_posix()}

    def _new_attempt(self, source, requested):
        return {"source": source, "status": "failed", "started_at": self.now().isoformat(), "finished_at": None,
                "requested": requested, "available": 0, "absent": 0, "failed": 0, "error": None, "provenances": []}

    def _journal(self, db, record):
        cursor = db.execute("INSERT INTO intelligence_attempts(source,status,payload) VALUES (?,?,?)", (record["source"], record["status"], "{}"))
        record["id"] = cursor.lastrowid
        db.execute("UPDATE intelligence_attempts SET payload=? WHERE id=?", (json.dumps(record, allow_nan=False), record["id"]))

    def _store(self, record, outcomes, token):
        with self.cisa.connect(timeout=self.commit_timeout) as db:
            db.execute("BEGIN IMMEDIATE")
            self._owned_lease(db, record["source"], token)
            self._journal(db, record)
            for value, (succeeded, data, provenance) in outcomes.items():
                db.execute("INSERT INTO intelligence_targets VALUES (?,?,?,?)", (record["id"], record["source"], value, int(succeeded)))
                if succeeded:
                    source_date = data["last_modified"] if data and record["source"] == "nvd" else data["date"] if data else None
                    db.execute("INSERT INTO intelligence_cache VALUES (?,?,?,?,?,?,?) ON CONFLICT(source,cve_id) DO UPDATE SET data=excluded.data,provenance=excluded.provenance,collected_at=excluded.collected_at,source_date=excluded.source_date,success_id=excluded.success_id",
                               (record["source"], value, json.dumps(data, allow_nan=False) if data is not None else None,
                                json.dumps(provenance), provenance["collected_at"], source_date, record["id"]))
            db.commit()

    def _finish(self, record, outcomes, token):
        record["finished_at"] = self.now().isoformat()
        record["available"] = sum(succeeded and data is not None for succeeded, data, _ in outcomes.values())
        record["absent"] = sum(succeeded and data is None for succeeded, data, _ in outcomes.values())
        record["failed"] = sum(not succeeded for succeeded, _, _ in outcomes.values())
        record["status"] = "partial" if record["failed"] and record["available"] + record["absent"] else "failed" if record["failed"] else "success"
        try:
            self._store(record, outcomes, token)
        except IntelligenceBusy:
            raise
        except Exception as error:
            record.pop("id", None)
            record.update(status="failed", available=0, absent=0, failed=record["requested"], error="Storage commit failed: " + str(error)[:1000])
            failed = {value: (False, None, None) for value in outcomes}
            try:
                self._store(record, failed, token)
            except IntelligenceBusy:
                raise
            except Exception as journal_error:
                record.pop("id", None)
                record["error"] += "; Failure journal not persisted: " + str(journal_error)[:500]
        if record["status"] == "failed":
            raise IntelligenceFailure(record)
        return record

    def _wait_next_request(self, source):
        with self.cisa.connect(snapshot=True) as db:
            next_start = db.execute("SELECT next_request FROM intelligence_control WHERE source=?", (source,)).fetchone()[0]
        delay = next_start - self.now().timestamp()
        if delay > 0:
            self.sleep(delay)

    def fetch_epss(self):
        with self.cisa.connect(snapshot=True) as db:
            ids = [row[0] for row in db.execute("SELECT cve_id FROM vulnerabilities ORDER BY cve_id")]
        batches = pack_epss(ids)
        token = self._acquire("epss")
        record = self._new_attempt("epss", len(ids))
        outcomes = {value: (False, None, None) for value in ids}
        errors = []
        try:
            for index, batch in enumerate(batches):
                deferred = False
                try:
                    if index:
                        self._wait_next_request("epss")
                    def received(response):
                        nonlocal deferred
                        if response.status_code == 429:
                            deferred = True
                            self._defer("epss", response.headers.get("retry-after"))
                    fetched = self.client.request("epss", batch, before_request=lambda: self._reserve_request("epss", token), on_response=received)
                    provenance = self._raw("epss", fetched)
                    record["provenances"].append(provenance)
                    if deferred:
                        raise ValueError("EPSS HTTP 429; remaining batches deferred to manual retry after source cooldown")
                    if fetched.status_code != 200:
                        raise ValueError("EPSS returned HTTP " + str(fetched.status_code))
                    parsed = parse_epss(fetched.raw, batch, self.now())
                    for value, data in parsed.items():
                        outcomes[value] = (True, data, provenance)
                except Exception as error:
                    errors.append("Batch " + str(index + 1) + ": " + str(error)[:500])
                if deferred:
                    break
            record["error"] = "; ".join(errors)[:2000] or None
            return self._finish(record, outcomes, token)
        finally:
            record.update(self._release("epss", token))

    def fetch_nvd(self, value, refresh=False):
        cached = self.get(value)["nvd"]
        if not refresh and cached["last_success"] is not None:
            return cached
        token = self._acquire("nvd")
        record, outcomes = self._new_attempt("nvd", 1), {value: (False, None, None)}
        try:
            try:
                def received(response):
                    if response.status_code == 429:
                        self._defer("nvd", response.headers.get("retry-after"))
                fetched = self.client.request("nvd", [value], before_request=lambda: self._reserve_request("nvd", token), on_response=received)
                provenance = self._raw("nvd", fetched)
                record["provenances"].append(provenance)
                if fetched.status_code != 200:
                    raise ValueError("NVD returned HTTP " + str(fetched.status_code))
                outcomes[value] = (True, parse_nvd(fetched.raw, value, self.now()), provenance)
            except Exception as error:
                record["error"] = str(error)[:1000]
            self._finish(record, outcomes, token)
        finally:
            cleanup = self._release("nvd", token)
            record.update(cleanup)
        return {**self.get(value)["nvd"], **cleanup}
