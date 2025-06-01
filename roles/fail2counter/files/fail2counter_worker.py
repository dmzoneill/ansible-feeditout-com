#!/usr/bin/env python3

import redis
import subprocess
import time
import requests
import os


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


# Load exploit list
with open(EXPLOITS_FILE, "r") as f:
    exploits_list = f.read()

# Prepare static prompt
system_prompt = f"""You are a cybersecurity expert helping choose Metasploit modules for post-breach analysis.

Below is a list of available Metasploit modules:

{exploits_list}

You will be given Nmap results for a scanned IP address. Using the list above, suggest which modules are likely applicable.
Only return valid Metasploit module paths from the list, no explanations.
"""

# Initialize Redis and OpenAI
r = redis.Redis(host='localhost', port=6379, db=0, password=os.environ.get("REDIS_PASSWORD"))
provider = OpenAIProvider()

while True:
    ip_entry = r.lpop(REDIS_QUEUE)
    if not ip_entry:
        time.sleep(10)
        continue

    _, ip = ip_entry.decode().split("|")

    print(f"[+] Scanning {ip}...")
    try:
        subprocess.run(
            ["timeout", str(SCAN_TIMEOUT), "nmap", "-A", "-T4", ip],
            check=True,
            stdout=open(TMP_OUTPUT, "w"),
            stderr=subprocess.DEVNULL
        )
    except subprocess.CalledProcessError:
        print(f"[!] Nmap scan failed or timed out for {ip}")
        continue

    with open(TMP_OUTPUT) as f:
        nmap_output = f.read()

    try:
        result = provider.improve_text(system_prompt, f"Nmap output:\n{nmap_output}")
        print(f"[+] Recommended Metasploit modules for {ip}:\n{result}")
    except Exception as e:
        print(f"[!] Failed to get module suggestions from OpenAI: {e}")