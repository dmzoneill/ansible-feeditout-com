"""Scheduled daily health digest."""

import importlib
import logging
import sqlite3
import time
from datetime import datetime, timedelta

import knowledge
from executor import execute_command

log = logging.getLogger("fio-bot")

# slack_sdk is installed with slack_bolt; loaded by name so this module's
# import block stays ordered the same way for isort, ruff and pylint.
SlackApiError = importlib.import_module("slack_sdk.errors").SlackApiError

DISK_WARN_PCT = 80
SSL_WARN_DAYS = 14

SSL_EXPIRY_CMD = (
    "for cert in /etc/letsencrypt/live/*/cert.pem; do"
    ' domain=$(basename $(dirname "$cert"));'
    ' expiry=$(openssl x509 -enddate -noout -in "$cert" 2>/dev/null'
    " | cut -d= -f2);"
    ' days=$(( ($(date -d "$expiry" +%s) - $(date +%s)) / 86400 ));'
    " echo \"$domain $days\"; done 2>/dev/null || echo ''"
)

_APT_LIST = "apt list --upgradable 2>/dev/null"
APT_UPGRADABLE_CMD = f"{_APT_LIST} | grep -c 'upgradable' || echo '0'"
_DOCKER_PS = "docker ps --format '{{.Names}} {{.Status}}' 2>/dev/null"
DOCKER_NOT_UP_CMD = f"{_DOCKER_PS} | grep -iv 'up' || echo ''"

FAIL2BAN_BANNED_CMD = (
    "fail2ban-client status 2>/dev/null"
    " | grep 'Jail list' | sed 's/.*://;s/,/\\n/g'"
    " | xargs -I{} fail2ban-client status {} 2>/dev/null"
    " | grep 'Currently banned'"
    " | awk '{sum += $NF} END {print sum+0}'"
)


def _check(cmd, timeout=10, max_output=2000):
    """Run a shell check and return (output, exit_code)."""
    return execute_command(cmd, timeout=timeout, max_output=max_output)


def _status_icon(ok):
    """Slack emoji for a passing or failing check."""
    return ":large_green_circle:" if ok else ":red_circle:"


def _to_int(text, default):
    """Parse text as an int, returning default when it is not a number."""
    try:
        return int(text)
    except ValueError:
        return default


def _disk_section():
    """Filesystems at or above DISK_WARN_PCT usage."""
    output, _ = _check("df -h -x devtmpfs -x tmpfs 2>/dev/null || df -h")
    high_use = []
    for line in output.split("\n"):
        parts = line.split()
        if len(parts) < 6 or not parts[4].endswith("%"):
            continue
        # Skip the "Use%" header row and anything else that is not a number.
        pct = _to_int(parts[4].rstrip("%"), None)
        if pct is not None and pct >= DISK_WARN_PCT:
            high_use.append(f"  {parts[5]} — *{parts[4]}* ({parts[3]} free)")
    if high_use:
        return f"{_status_icon(False)} *Disk Usage*\n" + "\n".join(high_use)
    return f"{_status_icon(True)} *Disk Usage* — All filesystems OK"


def _services_section():
    """Failed systemd units."""
    output, _ = _check("systemctl list-units --state=failed --no-pager --no-legend")
    if output.strip() and output.strip() != "(no output)":
        return f"{_status_icon(False)} *Failed Services*\n```\n{output}\n```"
    return f"{_status_icon(True)} *Services* — No failed units"


def _alerts_section(bot):
    """Current alert summary kept by the alerts loop."""
    with bot.alerts.summary_lock:
        summary = bot.alerts.summary
    if summary and "No alerts" in summary:
        return f"{_status_icon(True)} *Alerts* — None firing"
    if summary:
        return f"{_status_icon(False)} *Alerts*\n{summary}"
    return ":white_circle: *Alerts* — No data"


def _updates_section():
    """Pending apt upgrades."""
    output, _ = _check(APT_UPGRADABLE_CMD)
    pending = _to_int(output.strip().split("\n")[-1], 0)
    if pending > 0:
        return f":yellow_circle: *Updates* — {pending} package(s) pending"
    return f"{_status_icon(True)} *Updates* — System up to date"


def _containers_section():
    """Docker containers that are not up."""
    output, _ = _check(DOCKER_NOT_UP_CMD)
    unhealthy = [line for line in output.strip().split("\n") if line.strip()]
    if unhealthy:
        listing = "\n".join(f"  {c}" for c in unhealthy)
        return f"{_status_icon(False)} *Containers*\n" + listing
    running, _ = _check("docker ps --format '{{.Names}}' 2>/dev/null | wc -l")
    return f"{_status_icon(True)} *Containers* — {running.strip()} running"


def _apache_section():
    """Number of configured Apache VirtualHosts."""
    output, _ = _check("apachectl -S 2>&1 | grep -c 'VirtualHost'")
    vhosts = _to_int(output.strip(), -1)
    if vhosts >= 0:
        return f"{_status_icon(True)} *Apache* — {vhosts} VirtualHost(s) configured"
    return f"{_status_icon(False)} *Apache* — Unable to query status"


def _ssl_section():
    """Let's Encrypt certificates expiring within SSL_WARN_DAYS."""
    output, _ = _check(SSL_EXPIRY_CMD, timeout=15)
    expiring = []
    ssl_ok = 0
    for line in output.strip().split("\n"):
        parts = line.strip().split()
        if len(parts) != 2:
            continue
        days = _to_int(parts[1], None)
        if days is None:
            continue
        if days <= SSL_WARN_DAYS:
            expiring.append(f"  {parts[0]} — *{days} day(s)* remaining")
        else:
            ssl_ok += 1
    if expiring:
        return f"{_status_icon(False)} *SSL Certs*\n" + "\n".join(expiring)
    if ssl_ok > 0:
        return f"{_status_icon(True)} *SSL Certs* — {ssl_ok} cert(s) OK"
    return ":white_circle: *SSL Certs* — No certs found"


def _fail2ban_section():
    """Total IPs currently banned across fail2ban jails."""
    output, _ = _check(FAIL2BAN_BANNED_CMD)
    banned = _to_int(output.strip(), -1)
    if banned > 0:
        return f":yellow_circle: *Fail2ban* — {banned} IP(s) currently banned"
    if banned == 0:
        return f"{_status_icon(True)} *Fail2ban* — No banned IPs"
    return ":white_circle: *Fail2ban* — Unable to query status"


def _knowledge_section(bot):
    """Knowledge-base counts, or None when there is no database or it fails."""
    if not bot.db:
        return None
    try:
        stats = knowledge.get_stats(bot.db)
    except (sqlite3.Error, KeyError) as e:
        log.warning("Health digest: knowledge stats unavailable: %s", e)
        return None
    investigations, notes = stats["investigations"], stats["notes"]
    return f":brain: *Knowledge Base* — {investigations} investigations, {notes} notes"


def _build_digest(bot):
    """Collect every digest section in display order."""
    sections = [
        _disk_section(),
        _services_section(),
        _alerts_section(bot),
        _updates_section(),
        _containers_section(),
        _apache_section(),
        _ssl_section(),
        _fail2ban_section(),
        _knowledge_section(bot),
    ]
    return [section for section in sections if section]


def _seconds_until(hour):
    """Seconds from now until the next local hour:00."""
    now = datetime.now().astimezone()
    target = now.replace(hour=hour, minute=0, second=0, microsecond=0)
    if target <= now:
        target += timedelta(days=1)
    return (target - now).total_seconds()


def health_digest_loop(bot):
    """Post the health digest to Slack once a day at the configured hour."""
    if not bot.config.digest_enabled:
        log.info("Health digest disabled")
        return

    hour = bot.config.digest_hour
    log.info("Health digest scheduled for %02d:00 daily", hour)

    while True:
        wait = _seconds_until(hour)
        log.info("Next health digest in %.0f seconds", wait)
        time.sleep(wait)

        try:
            sections = _build_digest(bot)
            ts = datetime.now().astimezone().strftime("%A, %B %d %Y")
            header = f":clipboard: *Daily Health Digest — {ts}*\n"
            text = header + "\n\n".join(sections)

            bot.app.client.chat_postMessage(channel=bot.config.channel, text=text)
            log.info("Posted health digest")
        except (SlackApiError, OSError, ValueError) as e:
            log.error("Health digest error: %s", e)

        time.sleep(60)
