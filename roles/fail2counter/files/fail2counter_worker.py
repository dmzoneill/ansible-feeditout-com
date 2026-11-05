#!/usr/bin/env python3
"""Fail2Counter worker.

Consumes banned IPs from a Redis queue, performs nmap port and version scans
inside a VPN network namespace, stores results in PostgreSQL, runs AI-driven
exploit analysis, and emails a per-IP report.
"""

import os
import re
import smtplib
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Any

import ai
import psycopg2
import psycopg2.extras
import redis

# CONFIG
REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD")
REDIS_QUEUE = "banned_ips"
SCAN_TIMEOUT = 600
PRECHECK_TIMEOUT = 30
MIN_EXPECTED_OUTPUT_BYTES = 500
TMP_OUTPUT = os.path.join(tempfile.gettempdir(), "nmap_result.txt")
FASTSCAN_FILE = os.path.join(tempfile.gettempdir(), "nmap_fastscan.txt")
SCHEMA_FILE = "/opt/fail2counter/schema.sql"
VPN_ROTATE_INTERVAL = 30  # rotate VPN every N scans
VPN_SCRIPT = "/opt/fail2counter/vpn_namespace.sh"
NETNS = "msf_vpn"
NETNS_CMD = ["ip", "netns", "exec", NETNS]
DEFAULT_DSN = "host=/var/run/postgresql dbname=fail2counter user=fail2counter"
PG_DSN = os.environ.get("FAIL2COUNTER_DSN", DEFAULT_DSN)
DEFAULT_EMAIL = os.environ.get("FAIL2COUNTER_EMAIL", "dmz.oneill@gmail.com")

LOGS: list[str] = []


def _now() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def log(msg: str, level: str = "INFO") -> None:
    """Print a timestamped log line."""
    print(f"[{_now()}] [{level}] {msg}")


def capture(msg: str, level: str = "INFO") -> None:
    """Print and accumulate a timestamped log line for the email report."""
    log(msg, level)
    LOGS.append(f"[{_now()}] [{level}] {msg}")


@dataclass
class ServiceRecord:
    """Columns for a row in the services table."""

    port_id: int
    service_name: str
    product: str | None = None
    version: str | None = None
    is_ssl: bool = False
    recognized: bool = True


@dataclass
class ExploitRecord:
    """Columns for a row in the exploits table."""

    scan_id: int
    host_id: int
    module_path: str
    rhosts: str
    rport: int
    rc_path: str
    status: str = "suggested"


@dataclass
class NotificationRecord:
    """Columns for a row in the notifications table."""

    host_id: int
    exploit_id: int
    notification_type: str = "email"
    contact_info: str | None = None
    message: str | None = None


@dataclass
class ScanContext:
    """Per-IP scan state shared across the processing helpers."""

    ip: str
    hostname: str | None
    nmap_output: str
    host_id: int = 0
    scan_id: int = 0
    services: list[dict] = field(default_factory=list)


class Database:
    """Thin PostgreSQL wrapper for fail2counter inserts and schema setup."""

    def __init__(self, dsn: str):
        self._dsn = dsn
        self.conn: Any = None
        self.cursor: Any = None
        self.connect()

    def connect(self) -> None:
        """Open a new autocommit connection and dict cursor."""
        self.conn = psycopg2.connect(self._dsn)
        self.conn.autocommit = True
        self.cursor = self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    def ensure(self) -> None:
        """Reconnect if the current connection is dead."""
        try:
            self.cursor.execute("SELECT 1")
        except psycopg2.Error:
            self.connect()

    def commit(self) -> None:
        """Commit the current transaction."""
        self.conn.commit()

    def init_schema(self) -> None:
        """Initialise the database schema from schema.sql if present."""
        if not os.path.exists(SCHEMA_FILE):
            log("schema.sql not found, skipping schema init", "WARNING")
            return
        with open(SCHEMA_FILE, encoding="utf-8") as handle:
            sql = handle.read()
        self.cursor.execute(sql)
        log("Database schema initialized")

    def insert_host(self, ip: str, hostname: str | None) -> int:
        """Insert a host (or return the existing id) and return its id."""
        self.cursor.execute("SELECT id FROM hosts WHERE ip_address = %s", (ip,))
        row = self.cursor.fetchone()
        if row:
            return row["id"]
        self.cursor.execute(
            """INSERT INTO hosts (ip_address, hostname)
               VALUES (%s, %s) RETURNING id""",
            (ip, hostname),
        )
        return self.cursor.fetchone()["id"]

    def insert_scan(
        self,
        host_id: int,
        scan_type: str,
        start_time: datetime,
        latency: float,
        duration: float,
    ) -> int:
        """Insert a scan row and return its id."""
        self.cursor.execute(
            """INSERT INTO scans
               (host_id, scan_time, scan_type, latency_seconds, duration_seconds)
               VALUES (%s, %s, %s, %s, %s) RETURNING id""",
            (host_id, start_time, scan_type, latency, duration),
        )
        return self.cursor.fetchone()["id"]

    def insert_port(self, scan_id: int, port: int, protocol: str, state: str) -> int:
        """Insert a port row and return its id."""
        self.cursor.execute(
            """INSERT INTO ports (scan_id, port_number, protocol, state)
               VALUES (%s, %s, %s, %s) RETURNING id""",
            (scan_id, port, protocol, state),
        )
        return self.cursor.fetchone()["id"]

    def insert_service(self, service: ServiceRecord) -> None:
        """Insert a service row for a port."""
        self.cursor.execute(
            """INSERT INTO services
               (port_id, service_name, product, version, is_ssl, recognized)
               VALUES (%s, %s, %s, %s, %s, %s)""",
            (
                service.port_id,
                service.service_name,
                service.product,
                service.version,
                service.is_ssl,
                service.recognized,
            ),
        )

    def insert_exploit(self, exploit: ExploitRecord) -> int:
        """Insert an exploit row and return its id."""
        self.cursor.execute(
            """INSERT INTO exploits
               (scan_id, host_id, module_path, rhosts, rport, rc_file_path, status)
               VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id""",
            (
                exploit.scan_id,
                exploit.host_id,
                exploit.module_path,
                exploit.rhosts,
                exploit.rport,
                exploit.rc_path,
                exploit.status,
            ),
        )
        return self.cursor.fetchone()["id"]

    def insert_exploit_result(
        self,
        exploit_id: int,
        output_text: str,
        exit_code: int,
        duration: float,
    ) -> int:
        """Insert an exploit-result row and return its id."""
        self.cursor.execute(
            """INSERT INTO exploit_results
               (exploit_id, output_text, exit_code, duration_seconds)
               VALUES (%s, %s, %s, %s) RETURNING id""",
            (exploit_id, output_text, exit_code, duration),
        )
        return self.cursor.fetchone()["id"]

    def insert_notification(self, notification: NotificationRecord) -> int:
        """Insert a notification row and return its id."""
        self.cursor.execute(
            """INSERT INTO notifications
               (host_id, exploit_id, notification_type, status,
                contact_info, message)
               VALUES (%s, %s, %s, 'pending', %s, %s) RETURNING id""",
            (
                notification.host_id,
                notification.exploit_id,
                notification.notification_type,
                notification.contact_info,
                notification.message,
            ),
        )
        return self.cursor.fetchone()["id"]


def rotate_vpn() -> None:
    """Restart VPN in the network namespace to get a new exit IP."""
    try:
        result = subprocess.run(
            [VPN_SCRIPT, "restart-vpn"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        capture(f"VPN rotated: {result.stdout.strip()}")
    except (subprocess.SubprocessError, OSError) as exc:
        capture(f"VPN rotation failed: {exc}", level="WARNING")


def send_email(subject: str, body: str, to_email: str | None = None) -> None:
    """Send the per-IP analysis report by email."""
    recipient = to_email or DEFAULT_EMAIL
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = "root@feeditout.com"
    msg["To"] = recipient
    msg.set_content(body)

    try:
        with smtplib.SMTP("localhost") as server:
            server.send_message(msg)
        capture(f"Email sent to {recipient}")
    except (smtplib.SMTPException, OSError) as exc:
        capture(f"Failed to send email: {exc}", level="ERROR")


def connect_redis() -> redis.Redis | None:
    """Connect to Redis and verify the connection, or return None."""
    try:
        client = redis.Redis(
            host="localhost",
            port=int(os.environ.get("REDIS_PORT", "6379")),
            db=0,
            password=REDIS_PASSWORD,
        )
        client.ping()
        capture("Connected to Redis successfully.")
        return client
    except redis.exceptions.RedisError as exc:
        capture(f"Failed to connect to Redis: {exc}", level="ERROR")
        return None


def dequeue_ip(client: redis.Redis) -> tuple[str, str] | None:
    """Pop and parse the next (timestamp, ip) entry, or return None."""
    try:
        ip_entry = client.lpop(REDIS_QUEUE)
    except redis.exceptions.RedisError as exc:
        capture(f"Redis error while reading queue: {exc}", level="ERROR")
        time.sleep(10)
        return None

    if not ip_entry:
        time.sleep(10)
        return None

    try:
        timestamp, ip = ip_entry.decode().split("|")
    except (ValueError, AttributeError) as exc:
        capture(
            f"Failed to parse Redis queue entry: {ip_entry!r} - {exc}",
            level="ERROR",
        )
        return None

    capture(f"Dequeued IP: {ip} (banned at {timestamp})")
    return timestamp, ip


def _run_nmap(cmd: list[str], output_path: str | None) -> bool:
    """Run an nmap command, optionally to a file. Return True on success."""
    try:
        if output_path is None:
            subprocess.run(
                cmd,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        else:
            with open(output_path, "w", encoding="utf-8") as out:
                subprocess.run(cmd, check=True, stdout=out, stderr=out)
        return True
    except subprocess.CalledProcessError:
        return False


def precheck(ip: str) -> bool:
    """Return True if the host appears up, False if down or unreachable."""
    precheck_file = os.path.join(tempfile.gettempdir(), "nmap_precheck.txt")
    capture(f"Running precheck for {ip}")
    cmd = NETNS_CMD + ["timeout", str(PRECHECK_TIMEOUT), "nmap", "-sn", ip]
    try:
        with open(precheck_file, "w", encoding="utf-8") as out:
            subprocess.run(cmd, check=True, stdout=out, stderr=subprocess.DEVNULL)
        with open(precheck_file, encoding="utf-8") as handle:
            lines = handle.read()
        capture(lines, "INFO")
        if "Host seems down" in lines:
            capture(f"[SKIP] Host {ip} seems down")
            return False
        return True
    except subprocess.CalledProcessError:
        capture(f"[SKIP] Precheck failed or timed out for {ip}", level="WARNING")
        return False


def fast_scan(ip: str) -> str | None:
    """Run a fast port scan and return a comma-separated open-port list."""
    capture(f"Running fast port scan on {ip}")
    cmd = NETNS_CMD + [
        "timeout",
        str(SCAN_TIMEOUT),
        "nmap",
        "-T4",
        "-F",
        "-oG",
        FASTSCAN_FILE,
        "-v",
        ip,
    ]
    if not _run_nmap(cmd, None):
        capture(f"Fast scan failed for {ip}", level="ERROR")
        return None
    try:
        with open(FASTSCAN_FILE, encoding="utf-8") as handle:
            grepable = handle.read()
    except OSError as exc:
        capture(f"Fast scan failed: {exc}", level="ERROR")
        return None
    capture(grepable, "INFO")
    matches = re.findall(r"(\d+)/open", grepable)
    capture(str(matches), "DEBUG")
    ports = ",".join(matches)
    if not ports:
        capture(f"No open ports found on {ip}", level="WARNING")
        return None
    capture(f"Open ports: {ports}")
    return ports


def version_scan(ip: str, ports: str) -> str | None:
    """Run a service-version scan and return the nmap output text."""
    capture(f"Running service version detection for {ip}")
    cmd = NETNS_CMD + [
        "timeout",
        str(SCAN_TIMEOUT),
        "nmap",
        "-sV",
        "--version-light",
        "--max-retries",
        "1",
        "--min-parallelism",
        "10",
        "--host-timeout",
        "60s",
        "-p",
        ports,
        "-T4",
        "-v",
        ip,
    ]
    if _run_nmap(cmd, TMP_OUTPUT):
        capture(f"Scan completed for {ip}")
    else:
        capture(f"Nmap scan failed or timed out for {ip}", level="WARNING")

    try:
        with open(TMP_OUTPUT, encoding="utf-8") as handle:
            nmap_output = handle.read()
    except OSError as exc:
        capture(f"Failed to read Nmap output: {exc}", level="ERROR")
        return None
    capture(nmap_output, "DEBUG")
    if len(nmap_output) < MIN_EXPECTED_OUTPUT_BYTES:
        capture(f"Skipping {ip} due to small output", level="WARNING")
        return None
    capture(f"Nmap output size: {len(nmap_output)} bytes")
    return nmap_output


def resolve_hostname(ip: str) -> str | None:
    """Return the reverse-DNS hostname for an IP, or None."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None


def parse_services(nmap_output: str) -> list[dict]:
    """Parse open ports and service details from nmap output."""
    pattern = (
        r"(?P<port>\d+)/tcp\s+open\s+(?P<service>[^\s]+)"
        r"(?:\s+(?P<product>[^\s]+)(?:\s+(?P<version>[^\s]+))?)?"
    )
    detected = []
    for match in re.finditer(pattern, nmap_output):
        port = int(match.group("port"))
        service_name = match.group("service")
        is_ssl = "ssl" in service_name.lower() or port in (443, 465, 993, 995)
        detected.append(
            {
                "port": port,
                "service_name": service_name.rstrip("?"),
                "product": match.group("product") or None,
                "version": match.group("version") or None,
                "is_ssl": is_ssl,
                "recognized": not service_name.endswith("?"),
            }
        )
    return detected


def extract_timing(nmap_output: str) -> tuple[float, float]:
    """Return (latency, duration) parsed from nmap output, defaulting to 0."""
    latency_match = re.search(r"Host is up \(([\d.]+)s latency\)", nmap_output)
    duration_match = re.search(r"scanned in ([\d.]+) seconds", nmap_output)
    latency = float(latency_match.group(1)) if latency_match else 0.0
    duration = float(duration_match.group(1)) if duration_match else 0.0
    return latency, duration


def store_scan(db: Database, ctx: ScanContext) -> None:
    """Persist host, scan, ports and services onto the scan context."""
    ctx.host_id = db.insert_host(ctx.ip, ctx.hostname)
    latency, duration = extract_timing(ctx.nmap_output)
    scan_time = datetime.now(timezone.utc)
    ctx.scan_id = db.insert_scan(ctx.host_id, "version", scan_time, latency, duration)

    ctx.services = parse_services(ctx.nmap_output)
    for svc in ctx.services:
        port_id = db.insert_port(ctx.scan_id, svc["port"], "tcp", "open")
        db.insert_service(
            ServiceRecord(
                port_id=port_id,
                service_name=svc["service_name"],
                product=svc["product"],
                version=svc["version"],
                is_ssl=svc["is_ssl"],
                recognized=svc["recognized"],
            )
        )


def _store_exploit(db: Database, ctx: ScanContext, result: dict) -> int:
    """Persist a single exploit result and return its exploit id."""
    exploit_id = db.insert_exploit(
        ExploitRecord(
            scan_id=ctx.scan_id,
            host_id=ctx.host_id,
            module_path=result["module_path"],
            rhosts=result["rhosts"],
            rport=result["rport"],
            rc_path=result["rc_path"],
            status=result["status"],
        )
    )
    db.insert_exploit_result(
        exploit_id,
        result["output"],
        result["exit_code"],
        result["duration"],
    )
    return exploit_id


def _notify_success(db: Database, ctx: ScanContext, result: dict) -> None:
    """Create an abuse-contact notification for a confirmed vulnerability."""
    message = (
        f"Vulnerability confirmed on {ctx.ip} "
        f"({ctx.hostname or 'unknown'}):\n"
        f"Module: {result['module_path']}\n"
        f"Port: {result['rport']}\n"
        f"This host attacked our infrastructure and appears "
        f"to be compromised."
    )
    db.insert_notification(
        NotificationRecord(
            host_id=ctx.host_id,
            exploit_id=result["exploit_id"],
            notification_type="abuse_contact",
            message=message,
        )
    )


def run_analysis(
    db: Database,
    ctx: ScanContext,
    exploit_index: "ai.ExploitIndex",
) -> list[str]:
    """Run AI exploit analysis, persist results, return summary lines."""
    summary: list[str] = []
    if not ctx.services:
        return summary

    try:
        capture(f"Starting AI exploit analysis for {ctx.ip}...")
        ai_results = ai.analyze(
            ip=ctx.ip,
            nmap_output=ctx.nmap_output,
            services=ctx.services,
            exploit_index=exploit_index,
            log_fn=capture,
        )
        for result in ai_results:
            summary.append(_persist_result(db, ctx, result))
        count = len(ai_results)
        capture(f"AI exploit analysis complete: {count} modules tested")
    except (psycopg2.Error, KeyError, ValueError, TypeError) as exc:
        capture(f"AI exploit analysis failed: {exc}", level="ERROR")

    return summary


def _persist_result(db: Database, ctx: ScanContext, result: dict) -> str:
    """Persist one exploit result and return its summary line."""
    exploit_id = _store_exploit(db, ctx, result)
    result["exploit_id"] = exploit_id
    status = result["status"].upper()
    rport = result["rport"]
    if result["status"] == "success":
        _notify_success(db, ctx, result)
    loc = f"{result['rhosts']}:{rport}"
    dur = f"{result['duration']:.1f}s"
    return f"  [{status}] {result['module_path']} -> {loc} ({dur})"


def send_report(db: Database, ip: str, summary: list[str]) -> None:
    """Commit the transaction and email the per-IP report."""
    email_body = "\n".join(LOGS)
    if summary:
        email_body += "\n\n=== EXPLOIT ANALYSIS RESULTS ===\n"
        email_body += "\n".join(summary)

    try:
        capture("[DB] Attempting manual commit...", "DEBUG")
        db.commit()
        capture("[DB] Manual commit successful", "DEBUG")
    except psycopg2.Error as exc:
        capture(f"[DB] Manual commit failed: {exc}", "ERROR")

    send_email(subject=f"[Fail2Counter] Analysis for {ip}", body=email_body)


def handle_ip(db: Database, exploit_index: "ai.ExploitIndex", ip: str) -> bool:
    """Scan, analyse and report a single IP. Return True if a scan ran."""
    if not precheck(ip):
        return False
    ports = fast_scan(ip)
    if not ports:
        return False
    nmap_output = version_scan(ip, ports)
    if not nmap_output:
        return False

    ctx = ScanContext(
        ip=ip,
        hostname=resolve_hostname(ip),
        nmap_output=nmap_output,
    )
    store_scan(db, ctx)
    summary = run_analysis(db, ctx, exploit_index)
    send_report(db, ip, summary)
    return True


def process_next(
    db: Database,
    redis_client: redis.Redis,
    exploit_index: "ai.ExploitIndex",
    scan_count: int,
) -> int:
    """Process one queue entry and return the updated scan count."""
    db.ensure()
    LOGS.clear()
    entry = dequeue_ip(redis_client)
    if entry is None:
        return scan_count
    _, ip = entry
    if not handle_ip(db, exploit_index, ip):
        return scan_count
    scan_count += 1
    if scan_count % VPN_ROTATE_INTERVAL == 0:
        capture(f"Rotating VPN after {scan_count} scans...")
        rotate_vpn()
    return scan_count


def run_iteration(
    db: Database,
    redis_client: redis.Redis,
    exploit_index: "ai.ExploitIndex",
    scan_count: int,
) -> int:
    """Run one loop iteration, logging database errors instead of exiting."""
    try:
        return process_next(db, redis_client, exploit_index, scan_count)
    except psycopg2.Error as exc:
        capture(f"[DB] Database error, continuing: {exc}", level="ERROR")
        time.sleep(10)
        return scan_count


def main() -> None:
    """Run the worker loop: consume banned IPs and scan/analyse each."""
    if not REDIS_PASSWORD:
        capture("REDIS_PASSWORD environment variable is not set", level="ERROR")
        sys.exit(2)

    db = Database(PG_DSN)
    db.init_schema()

    capture("Loading exploit index...")
    exploit_index = ai.ExploitIndex()
    capture(f"Exploit index ready: {len(exploit_index.modules)} modules")

    redis_client = connect_redis()
    if redis_client is None:
        sys.exit(3)

    scan_count = 0
    while True:
        scan_count = run_iteration(db, redis_client, exploit_index, scan_count)


if __name__ == "__main__":
    main()
