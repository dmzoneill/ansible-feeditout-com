"""Command audit logging to Slack."""

import logging
from datetime import datetime, timezone

log = logging.getLogger("fio-bot")


def log_command(bot, user, command, args=""):
    channel = bot.config.audit_channel
    if not channel:
        return
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    cmd_str = f"/fio {command}"
    if args:
        cmd_str += f" {args[:80]}"
    text = f":clipboard: `{cmd_str}`\n" f"*User:* {user}  |  *Time:* {ts}"
    try:
        bot.app.client.chat_postMessage(channel=channel, text=text)
    except Exception as e:
        log.error("Audit log failed: %s", e)


def log_chat(bot, user, message):
    channel = bot.config.audit_channel
    if not channel:
        return
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    truncated = message[:100] + "..." if len(message) > 100 else message
    text = (
        f":speech_balloon: *Chat*\n"
        f"*User:* <@{user}>  |  *Time:* {ts}\n"
        f"> {truncated}"
    )
    try:
        bot.app.client.chat_postMessage(channel=channel, text=text)
    except Exception as e:
        log.error("Audit log failed: %s", e)


def log_remediation(bot, user, alert, command, exit_code):
    channel = bot.config.audit_channel
    if not channel:
        return
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    status = "OK" if exit_code == 0 else f"FAILED (exit {exit_code})"
    text = (
        f":wrench: *Remediation Executed*\n"
        f"*Alert:* {alert}  |  *Approved by:* {user}\n"
        f"*Command:* `{command}`\n"
        f"*Result:* {status}  |  *Time:* {ts}"
    )
    try:
        bot.app.client.chat_postMessage(channel=channel, text=text)
    except Exception as e:
        log.error("Audit log failed: %s", e)
