#!/usr/bin/env python3

import os
import re
import smtplib
import socket
import subprocess
import time
from datetime import datetime
from email.message import EmailMessage
from typing import List

import mysql.connector
import redis

db = mysql.connector.connect(
    host="localhost",
    user="fail2counter",
    password=os.environ.get("FAIL2COUNTER_PASSWORD"),
    database="fail2counter",
)
cursor = db.cursor(dictionary=True)


# CONFIG
REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD")
REDIS_QUEUE = "banned_ips"
SCAN_TIMEOUT = 600
PRECHECK_TIMEOUT = 30
MIN_EXPECTED_OUTPUT_BYTES = 500
TMP_OUTPUT = "/tmp/nmap_result.txt"
FASTSCAN_FILE = "/tmp/nmap_fastscan.txt"
logs: List[str] = []


def insert_host(ip: str, hostname: str) -> int:
    cursor.execute("SELECT id FROM hosts WHERE ip_address = %s", (ip,))
    row = cursor.fetchone()
    if row:
        return row["id"]
    cursor.execute(
        "INSERT INTO hosts (ip_address, hostname) VALUES (%s, %s)", (ip, hostname)
    )
    db.commit()
    return cursor.lastrowid


def insert_scan(
    host_id: int, scan_type: str, start_time: datetime, latency: float, duration: float
) -> int:
    cursor.execute(
        "INSERT INTO scans (host_id, scan_time, scan_type, latency_seconds, duration_seconds) VALUES (%s, %s, %s, %s, %s)",
        (host_id, start_time, scan_type, latency, duration),
    )
    db.commit()
    return cursor.lastrowid


def insert_port(scan_id: int, port: int, protocol: str, state: str) -> int:
    cursor.execute(
        "INSERT INTO ports (scan_id, port_number, protocol, state) VALUES (%s, %s, %s, %s)",
        (scan_id, port, protocol, state),
    )
    db.commit()
    return cursor.lastrowid


def insert_service(
    port_id: int,
    service_name: str,
    product: str = None,
    version: str = None,
    is_ssl=False,
    recognized=True,
):
    cursor.execute(
        "INSERT INTO services (port_id, service_name, product, version, is_ssl, recognized) VALUES (%s, %s, %s, %s, %s, %s)",
        (port_id, service_name, product, version, is_ssl, recognized),
    )
    db.commit()


def log(msg, level="INFO"):
    print(f"[{datetime.utcnow().isoformat()}] [{level}] {msg}")


def capture(msg, level="INFO"):
    log(msg, level)
    logs.append(f"[{datetime.utcnow().isoformat()}] [{level}] {msg}")


def send_email(subject: str, body: str, to_email="dmz.oneill@gmail.com"):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = "root@feeditout.com"
    msg["To"] = to_email
    msg.set_content(body)

    try:
        with smtplib.SMTP("localhost") as server:
            server.send_message(msg)
        capture(f"Email sent to {to_email}")
    except Exception as e:
        capture(f"Failed to send email: {e}", level="ERROR")


if not REDIS_PASSWORD:
    capture("REDIS_PASSWORD environment variable is not set", level="ERROR")
    exit(2)

try:
    r = redis.Redis(host="localhost", port=6379, db=0, password=REDIS_PASSWORD)
    r.ping()
    capture("Connected to Redis successfully.")
except Exception as e:
    capture(f"Failed to connect to Redis: {e}", level="ERROR")
    exit(3)

while True:
    try:
        ip_entry = r.lpop(REDIS_QUEUE)
    except Exception as e:
        capture(f"Redis error while reading queue: {e}", level="ERROR")
        time.sleep(10)
        logs = []
        continue

    if not ip_entry:
        capture("Queue empty, sleeping 10s...")
        time.sleep(10)
        logs = []
        continue

    try:
        timestamp, ip = ip_entry.decode().split("|")
        capture(f"Dequeued IP: {ip} (banned at {timestamp})")
    except Exception as e:
        capture(f"Failed to parse Redis queue entry: {ip_entry} — {e}", level="ERROR")
        logs = []
        continue

    # Precheck
    precheck_file = "/tmp/nmap_precheck.txt"
    capture(f"Running precheck for {ip}")
    try:
        subprocess.run(
            ["timeout", str(PRECHECK_TIMEOUT), "nmap", "-sn", ip],
            check=True,
            stdout=open(precheck_file, "w"),
            stderr=subprocess.DEVNULL,
        )
        with open(precheck_file) as f:
            lines = f.read()
            capture(lines, "INFO")
            if "Host seems down" in lines:
                capture(f"[SKIP] Host {ip} seems down")
                logs = []
                continue
    except subprocess.CalledProcessError:
        capture(f"[SKIP] Precheck failed or timed out for {ip}", level="WARNING")
        logs = []
        continue

    # Fast scan
    capture(f"Running fast port scan on {ip}")
    try:
        subprocess.run(
            [
                "timeout",
                str(SCAN_TIMEOUT),
                "nmap",
                "-T4",
                "-F",
                "-oG",
                FASTSCAN_FILE,
                "-v",
                ip,
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        with open(FASTSCAN_FILE) as f:
            lines = f.read()
            capture(lines, "INFO")
            grepable = lines
        matches = re.findall(r"(\d+)/open", grepable)
        capture(matches, "DEBUG")
        ports = ",".join(matches)
        if not ports:
            capture(f"No open ports found on {ip}", level="WARNING")
            logs = []
            continue
        capture(f"Open ports: {ports}")
    except Exception as e:
        capture(f"Fast scan failed: {e}", level="ERROR")
        logs = []
        continue

    # Version scan
    capture(f"Running service version detection for {ip}")
    try:
        with open(TMP_OUTPUT, "w") as out:
            subprocess.run(
                [
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
                ],
                check=True,
                stdout=out,
                stderr=out,
            )
        capture(f"Scan completed for {ip}")
    except subprocess.CalledProcessError:
        capture(f"Nmap scan failed or timed out for {ip}", level="WARNING")

    try:
        with open(TMP_OUTPUT) as f:
            nmap_output = f.read()
            capture(nmap_output, "DEBUG")
        if len(nmap_output) < MIN_EXPECTED_OUTPUT_BYTES:
            capture(f"Skipping {ip} due to small output", level="WARNING")
            logs = []
            continue
        capture(f"Nmap output size: {len(nmap_output)} bytes")
    except Exception as e:
        capture(f"Failed to read Nmap output: {e}", level="ERROR")
        logs = []
        continue

    # Resolve hostname
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        hostname = None

    host_id = insert_host(ip, hostname)

    scan_type = "version"
    scan_time = datetime.utcnow()

    # Extract latency and duration
    latency_match = re.search(r"Host is up \(([\d.]+)s latency\)", nmap_output)
    duration_match = re.search(r"scanned in ([\d.]+) seconds", nmap_output)
    latency = float(latency_match.group(1)) if latency_match else None
    duration = float(duration_match.group(1)) if duration_match else None

    scan_id = insert_scan(
        host_id, scan_type, scan_time, latency or 0.0, duration or 0.0
    )

    # Parse open ports and service details
    service_matches = re.finditer(
        r"(?P<port>\d+)/tcp\s+open\s+(?P<service>[^\s]+)(?:\s+(?P<product>[^\s]+)(?:\s+(?P<version>[^\s]+))?)?",
        nmap_output,
    )

    for match in service_matches:
        port = int(match.group("port"))
        service_name = match.group("service")
        product = match.group("product") or None
        version = match.group("version") or None

        is_ssl = "ssl" in service_name.lower() or port in (443, 465, 993, 995)
        recognized = not service_name.endswith("?")

        # Remove trailing '?' from service name if present
        clean_service_name = service_name.rstrip("?")

        port_id = insert_port(scan_id, port, "tcp", "open")
        insert_service(
            port_id, clean_service_name, product, version, is_ssl, recognized
        )

    send_email(subject=f"[Nmap Report] Analysis for {ip}", body="\n".join(logs))
    logs = []
