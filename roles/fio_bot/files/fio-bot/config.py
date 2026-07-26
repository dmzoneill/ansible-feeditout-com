"""Configuration loading and system prompts."""

import os
from dataclasses import dataclass, field


@dataclass
class Config:
    slack_bot_token: str
    slack_app_token: str
    opencode_api_key: str
    channel: str
    model: str
    api_base: str
    max_output: int
    command_timeout: int
    max_history: int
    github_repo: str
    idle_mention_user: str
    idle_interval: int
    prometheus_url: str
    alertmanager_url: str
    alert_poll_interval: int
    alert_cooldown_hours: int
    alert_cooldown_seconds: int
    alert_max_rounds: int
    alert_investigation_timeout: int
    server_hostname: str
    server_domain: str
    alert_channels: dict = field(default_factory=dict)  # populated at startup
    alert_channel_ids: set = field(default_factory=set)  # populated at startup
    channel_id_to_category: dict = field(default_factory=dict)  # populated at startup
    personality_file: str = "/etc/fio-bot/.fio-bot-personality"
    ansible_dir: str = "/opt/ansible"
    knowledge_db_path: str = "/opt/fio-bot/knowledge.db"
    kb_retention_days: int = 180
    kb_context_limit: int = 5
    kb_max_rows: int = 5000
    audit_channel: str = ""
    digest_enabled: bool = True
    digest_hour: int = 8


def load() -> Config:
    alert_cooldown_hours = int(os.environ.get("FIO_BOT_ALERT_COOLDOWN_HOURS", "4"))

    return Config(
        slack_bot_token=os.environ["SLACK_BOT_TOKEN"],
        slack_app_token=os.environ["SLACK_APP_TOKEN"],
        opencode_api_key=os.environ["OPENCODE_ZEN_API_KEY"],
        channel=os.environ.get("FIO_BOT_CHANNEL", "C0BJLKJG9U1"),
        model=os.environ.get("FIO_BOT_MODEL", "big-pickle"),
        api_base=os.environ.get("FIO_BOT_API_BASE", "https://opencode.ai/zen/v1"),
        max_output=int(os.environ.get("FIO_BOT_MAX_OUTPUT", "3000")),
        command_timeout=int(os.environ.get("FIO_BOT_COMMAND_TIMEOUT", "30")),
        max_history=int(os.environ.get("FIO_BOT_MAX_HISTORY", "20")),
        github_repo=os.environ.get(
            "FIO_BOT_GITHUB_REPO", "dmzoneill/ansible-feeditout-com"
        ),
        idle_mention_user=os.environ.get("FIO_BOT_IDLE_MENTION_USER", ""),
        idle_interval=int(os.environ.get("FIO_BOT_IDLE_INTERVAL", "21600")),
        prometheus_url=os.environ.get(
            "FIO_BOT_PROMETHEUS_URL", "http://localhost:9090"
        ),
        alertmanager_url=os.environ.get(
            "FIO_BOT_ALERTMANAGER_URL", "http://localhost:9093"
        ),
        alert_poll_interval=int(os.environ.get("FIO_BOT_ALERT_POLL_INTERVAL", "60")),
        alert_cooldown_hours=alert_cooldown_hours,
        alert_cooldown_seconds=alert_cooldown_hours * 3600,
        alert_max_rounds=int(os.environ.get("FIO_BOT_ALERT_MAX_ROUNDS", "3")),
        alert_investigation_timeout=int(
            os.environ.get("FIO_BOT_ALERT_INVESTIGATION_TIMEOUT", "20")
        ),
        server_hostname=os.environ.get("FIO_BOT_SERVER_HOSTNAME", "feeditout"),
        server_domain=os.environ.get("FIO_BOT_SERVER_DOMAIN", ""),
        ansible_dir=os.environ.get("FIO_BOT_ANSIBLE_DIR", "/opt/ansible"),
        knowledge_db_path=os.environ.get(
            "FIO_BOT_KB_PATH", "/opt/fio-bot/knowledge.db"
        ),
        kb_retention_days=int(os.environ.get("FIO_BOT_KB_RETENTION_DAYS", "180")),
        kb_context_limit=int(os.environ.get("FIO_BOT_KB_CONTEXT_LIMIT", "5")),
        kb_max_rows=int(os.environ.get("FIO_BOT_KB_MAX_ROWS", "5000")),
        audit_channel=os.environ.get("FIO_BOT_AUDIT_CHANNEL", ""),
        digest_enabled=os.environ.get("FIO_BOT_DIGEST_ENABLED", "true").lower()
        == "true",
        digest_hour=int(os.environ.get("FIO_BOT_DIGEST_HOUR", "8")),
    )


def _server_fqdn(cfg: Config) -> str:
    if cfg.server_domain:
        return f"{cfg.server_hostname}.{cfg.server_domain}"
    return cfg.server_hostname


def system_prompt(cfg: Config) -> str:
    return (
        "You are FIO Bot, a ChatOps assistant running on a web server called "
        + cfg.server_hostname
        + ".\n"
        "You have full shell access to the system. You can execute commands to answer questions or perform tasks.\n"
        "\n"
        "To execute a command, include a JSON block in your response like this:\n"
        "```command\n"
        '{"command": "your shell command here"}\n'
        "```\n"
        "\n"
        "To upload a file to the Slack thread, include a JSON block like this:\n"
        "```upload\n"
        '{"file": "/path/to/file", "title": "optional title"}\n'
        "```\n"
        "You can also upload content as a snippet (without needing a file on disk):\n"
        "```upload\n"
        '{"content": "file contents here", "filename": "example.txt", "title": "optional title"}\n'
        "```\n"
        "\n"
        "CRITICAL RULES:\n"
        "1. After a command executes, you will receive its output. ALWAYS include the actual result in your response.\n"
        "2. You may show the command, but you MUST also show the output or answer. Never just show a command with no result.\n"
        '3. If the user asks "yes or no", respond with a direct "yes" or "no" answer (you can include context but lead with the answer).\n'
        "4. If the user asks for a value (size, count, status), lead with that value.\n"
        "5. When the user asks you to attach, upload, or share a file, use the upload block to send it to the thread.\n"
        "6. Be concise. Use Slack mrkdwn formatting when helpful: *bold*, `inline code`, ```code blocks```.\n"
        "7. For destructive operations (rm -rf, reboot, DROP TABLE), warn the user first and ask for confirmation before executing.\n"
        "8. NEVER predict or assume command output. Do not write what a command will return — wait for the actual output. Do not include fake URLs, issue numbers, or results in your response alongside a command block.\n"
        "9. Only use ONE command block per response. Execute one command, wait for its output, then decide the next step.\n"
        "10. Do not include upload blocks in the same response as a command block. Upload only after you have confirmed real results from command output.\n"
        "\n"
        "You can create GitHub issues on the ansible-feeditout-com repository. To create an issue, use:\n"
        "```command\n"
        '{"command": "gh issue create --repo '
        + cfg.github_repo
        + " --title 'Issue title here' --body 'Issue description here'\"}\n"
        "```\n"
        "When asked to open or create a GitHub issue, extract a clear title and description from the user's request and create the issue. After creating the issue, include the issue URL in your response.\n"
        "You can also list issues with `gh issue list --repo "
        + cfg.github_repo
        + "` or view one with `gh issue view <number> --repo "
        + cfg.github_repo
        + "`.\n"
        "\n"
        "The server hostname is " + _server_fqdn(cfg) + ".\n"
        "You know this is a Debian 13 (Trixie) web server running Apache2, Postfix mail,\n"
        "MariaDB, Redis, PHP-FPM, Docker containers, Prometheus monitoring, Grafana,\n"
        "fail2ban, ClamAV, AIDE, certbot with wildcard SSL certs, and multiple domains.\n"
    )


def monitoring_reference(cfg: Config) -> str:
    return (
        "\nMONITORING & ALERTS:\n"
        "You have access to Prometheus ("
        + cfg.prometheus_url
        + ") and Alertmanager ("
        + cfg.alertmanager_url
        + ").\n"
        "The CURRENT ALERT STATUS section below shows what is firing right now. Reference it when users ask about alerts, health, or system status.\n"
        "\n"
        "To investigate further, use curl commands:\n"
        "- Firing alerts detail: curl -s '"
        + cfg.alertmanager_url
        + "/api/v2/alerts' | python3 -m json.tool\n"
        "- Active silences: curl -s '"
        + cfg.alertmanager_url
        + "/api/v2/silences' | python3 -m json.tool\n"
        "- PromQL query: curl -s '"
        + cfg.prometheus_url
        + "/api/v1/query?query=PROMQL_HERE' | python3 -m json.tool\n"
        "- Scrape targets: curl -s '"
        + cfg.prometheus_url
        + "/api/v1/targets' | python3 -m json.tool\n"
        "- Alert rules: curl -s '"
        + cfg.prometheus_url
        + "/api/v1/rules' | python3 -m json.tool\n"
        "\n"
        "SLACK ALERT CHANNELS:\n"
        "To read recent messages from an alert channel, include a block like this:\n"
        "```slack\n"
        '{"channel": "channel-name", "count": 5}\n'
        "```\n"
        "Available channels: " + ", ".join(cfg.alert_channels.keys()) + "\n"
        "Use this when users ask about recent alerts in a specific category, or to get more context on an alert.\n"
        "\n"
        "LOG SCANNING & ISSUE CREATION:\n"
        "When asked to check logs or journald for errors:\n"
        "1. Scan journald: journalctl -p err -b --no-pager --since '24 hours ago' | tail -100\n"
        "2. Scan specific unit: journalctl -u <unit> -p err --no-pager --since '24 hours ago'\n"
        "3. Scan /var/log files: grep -ri 'error\\|fatal\\|critical\\|failed\\|panic\\|segfault' /var/log/apache2/error.log /var/log/mail.log /var/log/auth.log 2>/dev/null | tail -50\n"
        "4. Scan application logs: grep -ri 'error\\|failed' /var/log/apache2/error.log /var/log/mail.log /var/log/auth.log 2>/dev/null | tail -30\n"
        "\n"
        "Before creating a GitHub issue for an error:\n"
        "- First check existing open issues: gh issue list --repo "
        + cfg.github_repo
        + " --state open\n"
        "- Group related errors together into a single issue\n"
        "- Only create issues for errors that don't already have an open issue\n"
        "- Include: clear title, log file/unit, relevant log lines, timestamp range, occurrence count\n"
        "- Skip rotated/compressed logs (.gz) unless explicitly asked\n"
    )


def alert_investigation_prompt(cfg: Config) -> str:
    fqdn = _server_fqdn(cfg)
    return (
        "You are FIO Bot investigating a firing alert on the web server "
        + fqdn
        + ".\n"
        "Your job is to run diagnostic commands and report what you find.\n"
        "\n"
        "RULES:\n"
        "1. You are READ-ONLY. Never run commands that modify state (no systemctl restart, no rm, no kill, no reboot).\n"
        "   Only use commands that read information: journalctl, systemctl status, cat, ls, df, free, top -bn1, ss, ip, curl, etc.\n"
        "2. You have a maximum of {max_rounds} commands. Be strategic — pick the most informative commands first.\n"
        "3. To run a command, respond with exactly one command block:\n"
        "   ```command\n"
        '   {{"command": "your diagnostic command here"}}\n'
        "   ```\n"
        "4. After receiving command output, either run another command (up to {max_rounds} total) or write your final findings.\n"
        "5. Your final response (with NO command block) should be a concise summary with:\n"
        "   - What the alert means\n"
        "   - What you found from the diagnostic commands\n"
        "   - Likely root cause (if identifiable)\n"
        "   - Suggested remediation steps\n"
        "6. Format findings in markdown suitable for a GitHub issue.\n"
        "7. Be concise. Focus on facts from command output, not speculation.\n"
        "\n"
        "You know this is a Debian 13 (Trixie) web server running Apache2, Postfix mail,\n"
        "MariaDB, Redis, PHP-FPM, Docker containers, Prometheus monitoring, Grafana,\n"
        "fail2ban, ClamAV, AIDE, certbot with wildcard SSL certs, and multiple domains.\n"
        "\n"
        "CURRENT ALERT:\n"
        "{alert_context}\n"
    )
