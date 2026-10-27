"""Read-only snapshot, frozen time, bounded reads and no implicit collection."""
from contextlib import closing
from datetime import timedelta
import hashlib
import json
import sqlite3

from fastapi.testclient import TestClient
import pytest

from test_backend import NOW, vulnerability
from test_triage import triage_api, seed_kev, seed_source, source_data, numeric_catalog


def test_missing_database_is_not_created_by_get(triage_api):
    client, cisa = triage_api
    cisa.db_path = cisa.db_path.parent / "missing.db"
    # Exercise the already-started app without re-running initialization.
    probe = TestClient(client.app, base_url="http://127.0.0.1:8007", raise_server_exceptions=False)
    try:
        response = probe.get("/api/triage")
        assert not cisa.db_path.exists(), "GET created an empty SQLite file"
        assert response.status_code == 503
        assert response.json() == {"detail": "Local triage snapshot unavailable"}
    finally:
        probe.close()


def test_snapshot_connection_is_readonly_and_explicitly_closed(triage_api, monkeypatch):
    client, _ = triage_api
    real_connect = sqlite3.connect
    opened = []
    def observed(*args, **kwargs):
        # Only the test inspects this handle from the client thread after the
        # endpoint worker returns; production keeps SQLite's thread guard.
        connection = real_connect(*args, **{**kwargs, "check_same_thread": False})
        opened.append((args, kwargs, connection))
        return connection
    monkeypatch.setattr(sqlite3, "connect", observed)
    assert client.get("/api/triage").status_code == 200
    assert len(opened) == 1
    args, kwargs, db = opened[0]
    assert kwargs.get("uri") is True and "mode=ro" in str(args[0])
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        db.execute("SELECT 1")


def files_under(directory):
    return {path.relative_to(directory).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in directory.rglob("*") if path.is_file()}


def test_get_preserves_database_files_old_apis_and_never_collects(numeric_catalog, monkeypatch):
    client, ids, _ = numeric_catalog
    cisa = client.app.state.service
    intelligence = client.app.state.intelligence
    paths = ["/api/health", "/api/summary", "/api/vulnerabilities", "/api/sync/status",
             "/api/vulnerabilities/" + ids[5], "/api/intelligence/" + ids[5],
             "/api/intelligence/status", "/api/intelligence/summary"]
    before_api = {path: client.get(path).json() for path in paths}
    before_files = files_under(cisa.db_path.parent)
    with cisa.connect() as db:
        # File equality is a DELETE-journal fixture check, not a WAL guarantee.
        assert db.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
        before_database = list(db.iterdump())
    def forbidden(*args, **kwargs):
        raise AssertionError("GET attempted collection, network, control lease or raw file creation")
    for owner, names in ((cisa, ("sync", "download", "save_raw")),
                         (intelligence, ("fetch_nvd", "fetch_epss", "_acquire", "_reserve_request", "_raw")),
                         (intelligence.client, ("request",))):
        for name in names:
            monkeypatch.setattr(owner, name, forbidden)
    for params in ({}, {"epss_min": 0, "nvd_state": "needs_attention"}, {"q": "' OR 1=1 --"}):
        response = client.get("/api/triage", params=params)
        assert response.status_code == 200, response.text
    assert client.post("/api/triage").status_code == 405
    with cisa.connect() as db:
        assert list(db.iterdump()) == before_database
    assert files_under(cisa.db_path.parent) == before_files
    assert {path: client.get(path).json() for path in paths} == before_api


def test_clean_wal_get_allows_coordination_without_application_writes(triage_api, monkeypatch):
    """P1B-RO-WAL-001: document existing mode=ro behavior, not a new feature."""
    client, cisa = triage_api
    intelligence = client.app.state.intelligence
    value = "CVE-2026-6100"
    original = vulnerability(value)
    seed_kev(cisa, original, provenance={"id": 7, "status": "success", "sha256": "c" * 64})
    seed_source(cisa, "nvd", value, source_data("nvd", value), failed=True)
    real_connect = sqlite3.connect
    schema_sql = "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name"
    # Only this synthetic fixture writer changes journal mode. A clean close
    # checkpoints its commits and removes sidecars before the GET under test.
    with closing(real_connect(cisa.db_path)) as writer:
        assert writer.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
        before_dump = list(writer.iterdump())  # All rows, histories and control.
        before_schema = writer.execute(schema_sql).fetchall()
    before_files = files_under(cisa.db_path.parent)
    assert set(before_files) == {cisa.db_path.name}
    opened, statements, denied, forbidden_calls = [], [], [], []
    allowed = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ,
               sqlite3.SQLITE_TRANSACTION, sqlite3.SQLITE_FUNCTION}

    def authorize(action, arg1, arg2, database, trigger):
        if action not in allowed:
            denied.append((action, arg1, arg2))
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    def observed(*args, **kwargs):
        opened.append((args, kwargs))
        db = real_connect(*args, **kwargs)
        db.set_trace_callback(statements.append)
        db.set_authorizer(authorize)
        return db

    def forbidden(*args, **kwargs):
        forbidden_calls.append(True)
        raise AssertionError("WAL GET attempted collection, network, control lease or raw file creation")

    # Observe and deny application SQL mutations without blocking SQLite's own
    # coordination files. Existing live-HTTP guard also remains active.
    with monkeypatch.context() as guarded:
        guarded.setattr(sqlite3, "connect", observed)
        for owner, names in ((cisa, ("sync", "download", "save_raw")),
                             (intelligence, ("fetch_nvd", "fetch_epss", "_acquire", "_reserve_request", "_raw")),
                             (intelligence.client, ("request",))):
            for name in names:
                guarded.setattr(owner, name, forbidden)
        response = client.get("/api/triage")
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["total"] == 1 and result["items"][0]["kev"] == original
    assert len(opened) == 1
    args, kwargs = opened[0]
    assert kwargs.get("uri") is True and str(args[0]).endswith("?mode=ro")
    assert "immutable" not in str(args[0]) and "nolock" not in str(args[0])
    assert denied == [] and forbidden_calls == []
    assert [sql.split()[0].upper() for sql in statements] == ["BEGIN", *["SELECT"] * 4, "COMMIT"]
    after_files = files_under(cisa.db_path.parent)
    assert set(after_files) == {cisa.db_path.name, cisa.db_path.name + "-wal", cisa.db_path.name + "-shm"}
    assert after_files[cisa.db_path.name] == before_files[cisa.db_path.name]
    assert cisa.db_path.with_name(cisa.db_path.name + "-wal").stat().st_size == 0
    assert cisa.db_path.with_name(cisa.db_path.name + "-shm").stat().st_size > 0
    # Verification is also read-only and explicitly closed before Windows cleanup.
    with closing(real_connect(cisa.db_path.resolve().as_uri() + "?mode=ro", uri=True)) as check:
        assert list(check.iterdump()) == before_dump
        assert check.execute(schema_sql).fetchall() == before_schema


def test_bulk_reads_never_load_attempt_payloads_and_freeze_one_instant(triage_api, monkeypatch):
    client, cisa = triage_api
    ids = [f"CVE-2026-{5000 + index}" for index in range(121)]
    seed_kev(cisa, *(vulnerability(value) for value in ids))
    for value in ids:
        seed_source(cisa, "epss", value, source_data("epss", value), age=timedelta(hours=23))
    with cisa.connect() as db:
        # Histories may contain huge batch URL lists. Compact GET must not read
        # or decode even one attempt (poisoning catches accidental reads).
        db.execute("UPDATE intelligence_attempts SET payload='not-json-never-read-by-triage'")
    real_connect, connections, statements, forbidden_reads = sqlite3.connect, [], [], []
    def authorize(action, table, *args):
        if action == sqlite3.SQLITE_READ and table in {"intelligence_attempts", "intelligence_control"}:
            forbidden_reads.append(table)
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK
    def observed(*args, **kwargs):
        db = real_connect(*args, **kwargs)
        connections.append(db)
        db.set_trace_callback(statements.append)
        db.set_authorizer(authorize)
        return db
    monkeypatch.setattr(sqlite3, "connect", observed)
    times = []
    def moving_clock():
        value = NOW + timedelta(days=8 * len(times))
        times.append(value)
        return value
    cisa.clock = moving_clock
    response = client.get("/api/triage", params={"page_size": 100})
    assert response.status_code == 200, response.text
    result = response.json()
    assert len(times) == 1 and result["as_of_utc"] == NOW.isoformat()
    assert len(connections) == 1 and forbidden_reads == []
    assert len([sql for sql in statements if sql.lstrip().upper().startswith("SELECT")]) == 4
    assert result["total"] == 121 and result["pages"] == 2 and len(result["items"]) == 100
    assert all(item["epss"]["state"] == "available" and not item["epss"]["stale"] for item in result["items"])


def test_concurrent_commit_cannot_mix_catalog_cache_targets_and_provenance(triage_api, monkeypatch):
    client, cisa = triage_api
    value = "CVE-2026-6000"
    old_kev = vulnerability(value)
    old_import = {"id": 1, "status": "success", "sha256": "a" * 64}
    seed_kev(cisa, old_kev, provenance=old_import)
    old_data = source_data("nvd", value)
    seed_source(cisa, "nvd", value, old_data)
    with cisa.connect() as db:
        assert db.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
    real_connect = sqlite3.connect
    committed, errors = [], []
    new_data = {**old_data, "cvss": []}
    new_kev = {**old_kev, "vendorProject": "Updated in separate committed transaction"}
    def interleave(sql):
        if "FROM imports" not in sql or committed:
            return
        committed.append(True)
        try:
            with closing(real_connect(cisa.db_path)) as writer:
                with writer:
                    writer.execute("UPDATE vulnerabilities SET payload=? WHERE cve_id=?", (json.dumps(new_kev), value))
                    writer.execute("UPDATE imports SET payload=? WHERE status='success'", (json.dumps({**old_import, "sha256": "b" * 64}),))
                    writer.execute("UPDATE intelligence_cache SET data=? WHERE source='nvd'", (json.dumps(new_data),))
                    writer.execute("INSERT INTO intelligence_targets VALUES (999,'nvd',?,0)", (value,))
        except Exception as error:
            errors.append(repr(error))
    def observed(*args, **kwargs):
        db = real_connect(*args, **kwargs)
        db.set_trace_callback(interleave)
        return db
    monkeypatch.setattr(sqlite3, "connect", observed)
    response = client.get("/api/triage")
    assert response.status_code == 200, response.text
    assert committed == [True] and errors == []
    result = response.json()
    assert result["cisa_provenance"] == old_import
    assert result["items"][0]["kev"] == old_kev
    assert result["items"][0]["nvd"]["data"] == old_data
    assert result["items"][0]["nvd"]["state"] == "available"
    after = client.get("/api/triage").json()
    assert after["items"][0]["kev"] == new_kev
    assert after["items"][0]["nvd"]["data"] == new_data
    assert after["items"][0]["nvd"]["state"] == "unavailable"
    assert after["cisa_provenance"]["sha256"] == "b" * 64
