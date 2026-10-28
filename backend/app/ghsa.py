"""Additive, explicitly requested GitHub Advisory Database intelligence."""
from datetime import datetime, timezone
import sqlite3
from .intelligence import IntelligenceService, IntelligenceBusy
from .ghsa_client import GhsaClient, parse_ghsa

ATTRIBUTION = {"name": "GitHub Advisory Database", "url": "https://github.com/advisories",
               "license": "CC-BY-4.0", "license_url": "https://creativecommons.org/licenses/by/4.0/"}


class GhsaService(IntelligenceService):
    def __init__(self, cisa):
        super().__init__(cisa)
        self.client = GhsaClient()

    def _acquire(self, source):
        # Only explicit uncached POST reaches this additive row creation.
        try:
            with self.cisa.connect(timeout=self.commit_timeout) as db:
                db.execute("INSERT OR IGNORE INTO intelligence_control(source) VALUES (?)", (source,))
            return super()._acquire(source)
        except sqlite3.OperationalError as error:
            if "locked" in str(error).lower():
                raise IntelligenceBusy("Database busy; collection not started") from error
            raise

    def _reserve_request(self, source, token):
        with self.cisa.connect(timeout=self.commit_timeout) as db:
            db.execute("BEGIN IMMEDIATE")
            row = self._owned_lease(db, source, token)
            now = self.now().timestamp()
            if row["next_request"] > now:
                raise IntelligenceBusy("Source request cooldown")
            db.execute("UPDATE intelligence_control SET next_request=?,lease_until=? WHERE source=? AND token=?",
                       (now + 65, now + 120, source, token))

    def _received(self, response):
        headers = response.headers
        if response.status_code in (403, 429) or "retry-after" in headers:
            self._defer("ghsa", headers.get("retry-after"))
        remaining, reset = headers.get("x-ratelimit-remaining", "").strip(), headers.get("x-ratelimit-reset", "").strip()
        if remaining == "0" and reset.isascii() and reset.isdigit():
            with self.cisa.connect(timeout=self.commit_timeout) as db:
                db.execute("UPDATE intelligence_control SET next_request=MAX(next_request,?) WHERE source='ghsa'", (float(reset),))

    def fetch(self, value, refresh=False):
        cached = self.get(value)
        if not refresh and cached["ghsa"]["last_success"] is not None:
            return cached
        token = self._acquire("ghsa")
        record, outcomes = self._new_attempt("ghsa", 1), {value: (False, None, None)}
        try:
            try:
                fetched = self.client.request(value, before_request=lambda: self._reserve_request("ghsa", token), on_response=self._received)
                provenance = {**self._raw("ghsa", fetched), "attribution": dict(ATTRIBUTION)}
                record["provenances"].append(provenance)
                if fetched.status_code != 200:
                    raise ValueError("GHSA returned HTTP " + str(fetched.status_code))
                outcomes[value] = (True, parse_ghsa(fetched.raw, value, self.now()), provenance)
            except Exception as error:
                record["error"] = str(error)[:1000]
            self._finish(record, outcomes, token)
        finally:
            cleanup = self._release("ghsa", token)
            record.update(cleanup)
        result = self.get(value)
        result["ghsa"].update(cleanup)
        return result

    def get(self, value):
        with self.cisa.connect(snapshot=True) as db:
            self._local_ids(db, [value])
            row = db.execute("SELECT next_request FROM intelligence_control WHERE source='ghsa'").fetchone()
            try:
                next_at = datetime.fromtimestamp(row[0], timezone.utc).isoformat() if row and row[0] else None
            except (ValueError, OverflowError, OSError):
                next_at = "deferred manual retry (source delay exceeds supported timestamp range)"
            return {"cve_id": value, "ghsa": self._view(db, "ghsa", value),
                    "control": {"next_request_at": next_at, "freshness_hours": 24,
                                "minimum_interval_seconds": 65, "max_advisories": 100,
                                "attribution": dict(ATTRIBUTION)}}
