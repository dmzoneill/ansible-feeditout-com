"""Scheduled daily health digest."""

import logging
import time
from datetime import datetime, timedelta

from executor import execute_command

log = logging.getLogger("fio-bot")


def _check(cmd, timeout=10, max_output=2000):
    output, exit_code = execute_command(cmd, timeout=timeout, max_output=max_output)
    return output, exit_code


def _status_icon(ok):
    return ":large_green_circle:" if ok else ":red_circle:"


def _build_digest(bot):
    sections = []

    # Disk usage
    output, _ = _check("df -h -x devtmpfs -x tmpfs 2>/dev/null || df -h")
    high_use = []
    for line in output.split("\n"):
        parts = line.split()
        if len(parts) >= 5 and parts[4].endswith("%"):
            pct = int(parts[4].rstrip("%"))
            if pct >= 80:
                high_use.append(f"  {parts[5]} — *{parts[4]}* ({parts[3]} free)")
    if high_use:
        sections.append(f"{_status_icon(False)} *Disk Usage*\n" + "\n".join(high_use))
    else:
        sections.append(f"{_status_icon(True)} *Disk Usage* — All filesystems OK")

    # Failed services
    output, _ = _check("systemctl list-units --state=failed --no-pager --no-legend")
    if output.strip() and output.strip() != "(no output)":
        sections.append(f"{_status_icon(False)} *Failed Services*\n```\n{output}\n```")
    else:
        sections.append(f"{_status_icon(True)} *Services* — No failed units")

    # Active alerts
    with bot.alert_summary_lock:
        summary = bot.alert_summary
    if summary and "No alerts" in summary:
        sections.append(f"{_status_icon(True)} *Alerts* — None firing")
    elif summary:
        sections.append(f"{_status_icon(False)} *Alerts*\n{summary}")
    else:
        sections.append(":white_circle: *Alerts* — No data")

    # Pending updates (Debian/apt)
    output, _ = _check(
        "apt list --upgradable 2>/dev/null | grep -c 'upgradable' || echo '0'"
    )
    count = output.strip().split("\n")[-1]
    try:
        n = int(count)
    except ValueError:
        n = 0
    if n > 0:
        sections.append(f":yellow_circle: *Updates* — {n} package(s) pending")
    else:
        sections.append(f"{_status_icon(True)} *Updates* — System up to date")

    # Docker containers
    output, _ = _check(
        "docker ps --format '{{.Names}} {{.Status}}' 2>/dev/null"
        " | grep -iv 'up' || echo ''"
    )
    unhealthy = [line for line in output.strip().split("\n") if line.strip()]
    if unhealthy:
        sections.append(
            f"{_status_icon(False)} *Containers*\n"
            + "\n".join(f"  {c}" for c in unhealthy)
        )
    else:
        output2, _ = _check("docker ps --format '{{.Names}}' 2>/dev/null | wc -l")
        n = output2.strip()
        sections.append(f"{_status_icon(True)} *Containers* — {n} running")

    # Apache status
    output, _ = _check("apachectl -S 2>&1 | grep -c 'VirtualHost'")
    count = output.strip()
    try:
        vhosts = int(count)
    except ValueError:
        vhosts = -1
    if vhosts >= 0:
        sections.append(
            f"{_status_icon(True)} *Apache* — {vhosts} VirtualHost(s) configured"
        )
    else:
        sections.append(f"{_status_icon(False)} *Apache* — Unable to query status")

    # SSL certificate expiry
    output, _ = _check(
        "for cert in /etc/letsencrypt/live/*/cert.pem; do"
        " domain=$(basename $(dirname \"$cert\"));"
        " expiry=$(openssl x509 -enddate -noout -in \"$cert\" 2>/dev/null"
        " | cut -d= -f2);"
        " days=$(( ($(date -d \"$expiry\" +%s) - $(date +%s)) / 86400 ));"
        " echo \"$domain $days\"; done 2>/dev/null || echo ''",
        timeout=15,
    )
    expiring = []
    ssl_ok = 0
    for line in output.strip().split("\n"):
        parts = line.strip().split()
        if len(parts) == 2:
            try:
                days = int(parts[1])
                if days <= 14:
                    expiring.append(f"  {parts[0]} — *{days} day(s)* remaining")
                else:
                    ssl_ok += 1
            except ValueError:
                pass
    if expiring:
        sections.append(
            f"{_status_icon(False)} *SSL Certs*\n" + "\n".join(expiring)
        )
    elif ssl_ok > 0:
        sections.append(
            f"{_status_icon(True)} *SSL Certs* — {ssl_ok} cert(s) OK"
        )
    else:
        sections.append(":white_circle: *SSL Certs* — No certs found")

    # Fail2ban banned count
    output, _ = _check(
        "fail2ban-client status 2>/dev/null"
        " | grep 'Jail list' | sed 's/.*://;s/,/\\n/g'"
        " | xargs -I{} fail2ban-client status {} 2>/dev/null"
        " | grep 'Currently banned'"
        " | awk '{sum += $NF} END {print sum+0}'"
    )
    count = output.strip()
    try:
        banned = int(count)
    except ValueError:
        banned = -1
    if banned > 0:
        sections.append(
            f":yellow_circle: *Fail2ban* — {banned} IP(s) currently banned"
        )
    elif banned == 0:
        sections.append(f"{_status_icon(True)} *Fail2ban* — No banned IPs")
    else:
        sections.append(":white_circle: *Fail2ban* — Unable to query status")

    # Knowledge base
    if bot.db:
        try:
            import knowledge

            stats = knowledge.get_stats(bot.db)
            sections.append(
                f":brain: *Knowledge Base* — {stats['investigations']}"
                f" investigations, {stats['notes']} notes"
            )
        except Exception:
            pass

    return sections


def _seconds_until(hour):
    now = datetime.now()
    target = now.replace(hour=hour, minute=0, second=0, microsecond=0)
    if target <= now:
        target += timedelta(days=1)
    return (target - now).total_seconds()


def health_digest_loop(bot):
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
            ts = datetime.now().strftime("%A, %B %d %Y")
            header = f":clipboard: *Daily Health Digest — {ts}*\n"
            text = header + "\n\n".join(sections)

            bot.app.client.chat_postMessage(channel=bot.config.channel, text=text)
            log.info("Posted health digest")
        except Exception as e:
            log.error("Health digest error: %s", e)

        time.sleep(60)
