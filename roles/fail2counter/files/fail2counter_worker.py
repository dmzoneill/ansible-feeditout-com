#!/usr/bin/env python3

import redis
import subprocess
import shlex
import time
import requests
import os
from datetime import datetime


class AiError(Exception):
    pass


class OpenAIProvider:
    def __init__(self) -> None:
        self.api_key: str = os.environ.get("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY is not set in the environment.")
        self.endpoint: str = "https://api.openai.com/v1/chat/completions"
        self.model: str = "gpt-4o-mini"

    def improve_text(self, prompt: str, text: str) -> str:
        headers: dict[str, str] = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        body: dict = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": prompt},
                {"role": "user", "content": text},
            ],
            "temperature": 0.4,
        }

        response: requests.post(self.endpoint, json=body, headers=headers, timeout=120)
        if response.status_code == 200:
            return response.json()["choices"][0]["message"]["content"].strip()

        raise AiError(
            f"OpenAI API call failed: {response.status_code} - {response.text}"
        )


# CONFIG
REDIS_QUEUE = "banned_ips"
SCAN_TIMEOUT = 600  # 10 minutes
TMP_OUTPUT = "/tmp/nmap_result.txt"
EXPLOITS_FILE = "/opt/fail2counter/exploits.txt"
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")


def log(msg, level="INFO"):
    print(f"[{datetime.utcnow().isoformat()}] [{level}] {msg}")

# Load exploit list
log(f"Loading Metasploit module list from {EXPLOITS_FILE}")
if not os.path.exists(EXPLOITS_FILE):
    log(f"Exploit list not found: {EXPLOITS_FILE}", level="ERROR")
    exit(1)

with open(EXPLOITS_FILE, "r") as f:
    exploits_list = f.read()

log(f"Loaded {len(exploits_list.splitlines())} Metasploit modules.")

# Prepare system prompt
system_prompt = f"""You are a cybersecurity expert helping choose Metasploit modules for post-breach analysis.

Below is a list of available Metasploit modules:

{exploits_list}

You will be given Nmap results for a scanned IP address. Using the list above, suggest which modules are likely applicable.
Only return valid Metasploit module paths from the list, no explanations.
"""

# Initialize Redis and OpenAI
REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD")
if not REDIS_PASSWORD:
    log("REDIS_PASSWORD environment variable is not set", level="ERROR")
    exit(2)

try:
    r = redis.Redis(host='localhost', port=6379, db=0, password=REDIS_PASSWORD)
    r.ping()
    log("Connected to Redis successfully.")
except Exception as e:
    log(f"Failed to connect to Redis: {e}", level="ERROR")
    exit(3)

provider = OpenAIProvider()

PRECHECK_TIMEOUT = 30  # seconds
MIN_EXPECTED_OUTPUT_BYTES = 500  # arbitrary threshold to filter useless scans

while True:
    try:
        ip_entry = r.lpop(REDIS_QUEUE)
    except Exception as e:
        log(f"Redis error while reading queue: {e}", level="ERROR")
        time.sleep(10)
        continue

    if not ip_entry:
        log("Queue empty, sleeping 10s...")
        time.sleep(10)
        continue

    try:
        timestamp, ip = ip_entry.decode().split("|")
        log(f"Dequeued IP: {ip} (banned at {timestamp})")
    except Exception as e:
        log(f"Failed to parse Redis queue entry: {ip_entry} — {e}", level="ERROR")
        continue

    # 🧪 Precheck: ping + fast scan
    precheck_file = "/tmp/nmap_precheck.txt"
    log(f"Running precheck for {ip} (timeout {PRECHECK_TIMEOUT}s)")
    try:
        precheck_start = time.time()
        subprocess.run(
            ["timeout", str(PRECHECK_TIMEOUT), "nmap", "-sn", ip],
            check=True,
            stdout=open(precheck_file, "w"),
            stderr=subprocess.DEVNULL
        )
        elapsed = time.time() - precheck_start
        with open(precheck_file, "r") as f:
            content = f.read()

        if "Host seems down" in content or "0 hosts up" in content:
            log(f"[SKIP] Host {ip} seems down after precheck ({elapsed:.1f}s)")
            continue

        log(f"[PASS] Precheck succeeded in {elapsed:.1f}s for {ip}")
    except subprocess.CalledProcessError:
        log(f"[SKIP] Precheck failed or timed out for {ip}", level="WARNING")
        continue

    # 🛠 Full scan
    log(f"Starting Nmap scan for {ip} (timeout {SCAN_TIMEOUT}s)")
    try:
        scan_start = time.time()
        with open(TMP_OUTPUT, "w") as out:
            subprocess.run(
                ["timeout", str(SCAN_TIMEOUT), "nmap", "-A", "-T4", "-v", ip],
                check=True,
                stdout=out,
                stderr=out  # 👈 capture stderr too
            )

        duration = time.time() - scan_start
        log(f"Nmap scan complete in {duration:.1f}s: output saved to {TMP_OUTPUT}")
    except subprocess.CalledProcessError:
        log(f"Nmap scan failed or timed out for {ip}", level="WARNING")
        continue

    try:
        with open(TMP_OUTPUT) as f:
            nmap_output = f.read()

        if len(nmap_output) < MIN_EXPECTED_OUTPUT_BYTES:
            log(f"Skipping {ip} due to minimal scan output ({len(nmap_output)} bytes)", level="WARNING")
            continue

        log(f"Nmap output read: {len(nmap_output)} bytes")
    except Exception as e:
        log(f"Failed to read Nmap output: {e}", level="ERROR")
        continue

    try:
        log(f"Sending Nmap output to OpenAI for {ip}...")
        result = provider.improve_text(system_prompt, f"Nmap output:\n{nmap_output}")
        log(f"OpenAI response received for {ip}:")
        print(result)
    except Exception as e:
        log(f"OpenAI processing failed for {ip}: {e}", level="ERROR")
