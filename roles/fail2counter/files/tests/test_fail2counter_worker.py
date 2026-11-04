"""Behaviour tests for the refactored ``fail2counter_worker`` module."""

import types

import ai
import fail2counter_worker as worker


class FakeCursor:
    """Minimal cursor recording executed SQL and returning queued rows."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple]] = []
        self.rows: list[dict] = []

    def execute(self, sql: str, params: tuple = ()) -> None:
        """Record an executed statement and its parameters."""
        self.calls.append((sql, params))

    def fetchone(self) -> dict:
        """Return the next queued row (an id dict by default)."""
        if self.rows:
            return self.rows.pop(0)
        return {"id": 1}

    def fetchall(self) -> list:
        """Return no rows (unused by the worker)."""
        return []


def _make_db() -> worker.Database:
    """Build a Database bound to a FakeCursor without connecting."""
    db = worker.Database.__new__(worker.Database)
    db.conn = None
    db.cursor = FakeCursor()
    return db


def test_parse_services_extracts_ports() -> None:
    """Open TCP services are parsed with product and ssl detection."""
    output = "443/tcp open ssl/https nginx 1.25\n22/tcp open ssh OpenSSH 9.0\n"
    services = worker.parse_services(output)
    by_port = {svc["port"]: svc for svc in services}
    assert by_port[443]["is_ssl"] is True
    assert by_port[22]["service_name"] == "ssh"
    assert by_port[22]["product"] == "OpenSSH"


def test_parse_services_strips_unknown_marker() -> None:
    """A trailing '?' marks the service unrecognised and is stripped."""
    services = worker.parse_services("8080/tcp open http?\n")
    assert services[0]["service_name"] == "http"
    assert services[0]["recognized"] is False


def test_extract_timing_defaults_to_zero() -> None:
    """Missing latency/duration values default to 0.0."""
    assert worker.extract_timing("no timing here") == (0.0, 0.0)


def test_extract_timing_parses_values() -> None:
    """Latency and duration are parsed from nmap output."""
    text = "Host is up (0.0125s latency). Nmap done scanned in 3.5 seconds"
    latency, duration = worker.extract_timing(text)
    assert latency == 0.0125
    assert duration == 3.5


def test_insert_host_returns_existing_id() -> None:
    """An existing host is returned without a second insert."""
    db = _make_db()
    db.cursor.rows = [{"id": 42}]
    assert db.insert_host("192.0.2.1", "host.example") == 42
    assert len(db.cursor.calls) == 1


def test_insert_host_creates_new_row() -> None:
    """A missing host triggers an insert and returns the new id."""
    db = _make_db()
    db.cursor.rows = [None, {"id": 7}]
    assert db.insert_host("192.0.2.2", None) == 7
    assert len(db.cursor.calls) == 2


def test_store_scan_populates_context() -> None:
    """store_scan fills host/scan ids and the parsed services."""
    db = _make_db()
    ctx = worker.ScanContext(
        ip="192.0.2.3",
        hostname=None,
        nmap_output="22/tcp open ssh OpenSSH 9.0\n",
    )
    worker.store_scan(db, ctx)
    assert ctx.host_id == 1
    assert ctx.scan_id == 1
    assert ctx.services[0]["service_name"] == "ssh"


def test_run_analysis_persists_and_summarises(monkeypatch) -> None:
    """A successful exploit is stored and produces a summary line."""
    db = _make_db()
    ctx = worker.ScanContext(
        ip="192.0.2.4",
        hostname="host",
        nmap_output="",
        host_id=1,
        scan_id=1,
        services=[{"service_name": "ssh"}],
    )
    result = {
        "module_path": "exploit/linux/ssh/x",
        "rhosts": "192.0.2.4",
        "rport": 22,
        "rc_path": "/tmp/x.rc",
        "status": "success",
        "output": "session opened",
        "exit_code": 0,
        "duration": 1.2,
    }
    monkeypatch.setattr(worker.ai, "analyze", lambda **_kwargs: [result])
    index = ai.ExploitIndex.__new__(ai.ExploitIndex)
    summary = worker.run_analysis(db, ctx, index)
    assert len(summary) == 1
    assert "[SUCCESS]" in summary[0]
    assert "192.0.2.4:22" in summary[0]


def test_run_analysis_skips_without_services() -> None:
    """No detected services means no analysis and an empty summary."""
    db = _make_db()
    ctx = worker.ScanContext(ip="192.0.2.6", hostname=None, nmap_output="")
    index = ai.ExploitIndex.__new__(ai.ExploitIndex)
    assert not worker.run_analysis(db, ctx, index)


def test_dequeue_ip_parses_entry() -> None:
    """A queue entry of 'timestamp|ip' is decoded into a tuple."""
    client = types.SimpleNamespace(lpop=lambda _queue: b"2026-01-01T00:00:00|192.0.2.7")
    entry = worker.dequeue_ip(client)
    assert entry == ("2026-01-01T00:00:00", "192.0.2.7")
