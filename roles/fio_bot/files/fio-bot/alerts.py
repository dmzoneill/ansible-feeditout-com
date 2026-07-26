"""Alert parsing, investigation, polling, and worker loop."""

import json
import logging
import re
import time
import urllib.request
from datetime import datetime, timezone

import knowledge
from config import alert_investigation_prompt
from executor import execute_command
from github import search_existing_issue, create_alert_issue, comment_on_issue
from llm import extract_commands, strip_actions

log = logging.getLogger("fio-bot")


def _extract_field(text, field_name):
    match = re.search(rf"\*{field_name}:\*\s*(.+)", text)
    if match:
        return match.group(1).strip()
    match = re.search(rf"(?:^|\n)\s*\*?{field_name}:\*?\s*(.+)", text, re.IGNORECASE)
    return match.group(1).strip() if match else None


def _collect_text(event):
    parts = []
    for att in event.get("attachments", []):
        for key in ("title", "text", "fallback", "pretext"):
            val = att.get(key, "")
            if val:
                parts.append(val)
        for field in att.get("fields", []):
            t = field.get("title", "")
            v = field.get("value", "")
            if t and v:
                parts.append(f"{t}: {v}")
    for block in event.get("blocks", []):
        if block.get("type") == "header":
            parts.append(block.get("text", {}).get("text", ""))
        elif block.get("type") == "section":
            txt = block.get("text", {}).get("text", "")
            if txt:
                parts.append(txt)
            for field in block.get("fields", []):
                parts.append(field.get("text", ""))
    if event.get("text"):
        parts.append(event["text"])
    return "\n".join(parts)


ALERT_KEYWORDS = re.compile(
    r"FIRING|UNHEALTHY|CRITICAL|DEGRADED|DOWN|FAILED|ERROR|ALERT",
    re.IGNORECASE,
)


def parse_alert_from_event(event, channel_id_to_category):
    full_text = _collect_text(event)
    if not full_text or not ALERT_KEYWORDS.search(full_text):
        return None

    channel = event.get("channel", "")
    category = channel_id_to_category.get(channel, "unknown")

    title_match = re.search(r"\[FIRING:\d+\]\s+(.+)", full_text)
    if title_match:
        alertname = title_match.group(1).strip()
        alertname = re.sub(r"^\*?Alert:\*?\s*", "", alertname).strip()
    else:
        for att in event.get("attachments", []):
            t = att.get("title", "")
            if t:
                alertname = t.strip()
                break
        else:
            for block in event.get("blocks", []):
                if block.get("type") == "header":
                    alertname = block.get("text", {}).get("text", "").strip()
                    break
            else:
                first_line = full_text.split("\n")[0].strip()
                alertname = first_line[:120] if first_line else "UnknownAlert"

    severity = _extract_field(full_text, "Severity") or "unknown"
    instance = (
        _extract_field(full_text, "Instance")
        or _extract_field(full_text, "Host")
        or "unknown"
    )
    summary = (
        _extract_field(full_text, "Summary") or _extract_field(full_text, "Event") or ""
    )

    description = ""
    for line in full_text.split("\n"):
        line = line.strip()
        if line and not re.match(r"^\*?\w+:\*?\s", line) and line != alertname:
            description += line + "\n"
    description = description.strip()

    status = "FIRING"
    if re.search(r"RESOLVED|RECOVERED", full_text, re.IGNORECASE):
        status = "RESOLVED"

    return {
        "alertname": alertname,
        "severity": severity.lower(),
        "instance": instance,
        "summary": summary,
        "description": description,
        "category": category,
        "status": status,
    }


def is_on_cooldown(bot, alertname, instance):
    key = (alertname, instance)
    with bot.alert_cooldowns_lock:
        last_seen = bot.alert_cooldowns.get(key, 0)
        return (time.time() - last_seen) < bot.config.alert_cooldown_seconds


def mark_processed(bot, alertname, instance):
    key = (alertname, instance)
    with bot.alert_cooldowns_lock:
        bot.alert_cooldowns[key] = time.time()


def maybe_enqueue_alert(bot, event, channel, client):
    if event.get("thread_ts"):
        return

    alert_info = parse_alert_from_event(event, bot.config.channel_id_to_category)
    if not alert_info:
        return

    if alert_info["status"] == "RESOLVED":
        log.info("Skipping resolved alert: %s", alert_info["alertname"])
        return

    cooldown_only = False
    if is_on_cooldown(bot, alert_info["alertname"], alert_info["instance"]):
        log.info(
            "Alert %s on %s is on cooldown, will skip re-investigation",
            alert_info["alertname"],
            alert_info["instance"],
        )
        cooldown_only = True

    alert_info["cooldown_only"] = cooldown_only
    alert_info["channel"] = channel
    alert_info["thread_ts"] = event["ts"]
    alert_info["client"] = client

    bot.alert_queue.put(alert_info)
    log.info(
        "Enqueued alert investigation: %s (%s)",
        alert_info["alertname"],
        alert_info["instance"],
    )


def _post_thread(client, channel, thread_ts, text):
    try:
        client.chat_postMessage(channel=channel, thread_ts=thread_ts, text=text)
    except Exception as e:
        log.error("Failed to post thread reply: %s", e)


REMEDIATION_PROMPT = (
    "Based on the investigation findings, suggest a single shell command"
    " that would fix or mitigate this alert.\n"
    "Only suggest commands that are safe and reversible"
    " (restart a service, clear a cache, kill a process).\n"
    "Never suggest destructive commands (rm -rf, reboot).\n"
    "If no remediation is appropriate, respond with exactly: none\n"
    "Respond with ONLY the command, nothing else."
)


def _suggest_remediation(bot, alert_info, findings):
    try:
        response = bot.llm.chat.completions.create(
            model=bot.config.model,
            messages=[
                {"role": "system", "content": REMEDIATION_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Alert: {alert_info['alertname']}\n"
                        f"Summary: {alert_info.get('summary', '')}\n"
                        f"Findings:\n{findings}"
                    ),
                },
            ],
            max_tokens=256,
        )
        suggestion = (response.choices[0].message.content or "").strip()
        if suggestion.lower() in ("none", "no remediation needed", "n/a", ""):
            return None
        return suggestion
    except Exception as e:
        log.error("Remediation suggestion error: %s", e)
        return None


def _post_remediation_buttons(client, channel, thread_ts, alertname, suggestion):
    blocks = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f":wrench: *Suggested remediation:*\n`{suggestion}`",
            },
        },
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Approve"},
                    "style": "primary",
                    "action_id": "approve_remediation",
                    "value": json.dumps({"cmd": suggestion, "alert": alertname}),
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Reject"},
                    "style": "danger",
                    "action_id": "reject_remediation",
                    "value": alertname,
                },
            ],
        },
    ]
    try:
        client.chat_postMessage(
            channel=channel,
            thread_ts=thread_ts,
            blocks=blocks,
            text=f"Suggested remediation: {suggestion}",
        )
    except Exception as e:
        log.error("Failed to post remediation buttons: %s", e)


def investigate_alert(bot, alert_info, past_investigations=None):
    cfg = bot.config
    alert_context = (
        f"Alert: {alert_info['alertname']}\n"
        f"Severity: {alert_info['severity']}\n"
        f"Instance: {alert_info['instance']}\n"
        f"Category: {alert_info['category']}\n"
        f"Summary: {alert_info['summary']}\n"
        f"Description: {alert_info.get('description', '')}\n"
    )

    prompt = alert_investigation_prompt(cfg).format(
        alert_context=alert_context,
        max_rounds=cfg.alert_max_rounds,
    )

    if past_investigations:
        history_lines = ["\nPREVIOUS INVESTIGATIONS FOR THIS ALERT:"]
        for inv in past_investigations:
            history_lines.append(
                f"\n[{inv['created_at']}] Severity: {inv.get('severity', '?')},"
                f" Instance: {inv.get('instance', '?')}"
            )
            findings = inv.get("findings", "")
            if len(findings) > 500:
                findings = findings[:500] + "..."
            history_lines.append(f"Findings: {findings}")
        history_lines.append(
            "\nUse this context to inform your investigation."
            " Note patterns or recurring issues."
        )
        prompt += "\n".join(history_lines)

    messages = [
        {"role": "system", "content": prompt},
        {
            "role": "user",
            "content": (
                f"Investigate this alert: {alert_info['alertname']} "
                f"--- {alert_info['summary']}"
            ),
        },
    ]

    all_output_parts = []

    for round_num in range(cfg.alert_max_rounds + 1):
        try:
            response = bot.llm.chat.completions.create(
                model=cfg.model,
                messages=messages,
                max_tokens=2048,
            )
        except Exception as e:
            log.error("LLM error during investigation: %s", e)
            all_output_parts.append(f"(LLM error: {e})")
            break

        reply = response.choices[0].message.content or ""
        commands = extract_commands(reply)
        display_text = strip_actions(reply)

        if not commands:
            if display_text:
                all_output_parts.append(display_text)
            break

        if round_num >= cfg.alert_max_rounds:
            if display_text:
                all_output_parts.append(display_text)
            all_output_parts.append("(Investigation round limit reached)")
            break

        messages.append({"role": "assistant", "content": reply})

        cmd = commands[0]
        output, exit_code = execute_command(cmd, cfg.command_timeout, cfg.max_output)
        code_indicator = "" if exit_code == 0 else f" (exit {exit_code})"

        all_output_parts.append(
            f"**Command:** `{cmd}`{code_indicator}\n```\n{output}\n```"
        )

        messages.append(
            {
                "role": "user",
                "content": (
                    f"[SYSTEM] Command `{cmd}` returned{code_indicator}:\n"
                    f"```\n{output}\n```\n"
                    f"You have {cfg.alert_max_rounds - round_num - 1} commands remaining. "
                    f"Run another diagnostic command or provide your final findings."
                ),
            }
        )

    return (
        "\n\n".join(all_output_parts) if all_output_parts else "(No findings produced)"
    )


def process_alert(bot, alert_data):
    client = alert_data["client"]
    channel = alert_data["channel"]
    thread_ts = alert_data["thread_ts"]
    alertname = alert_data["alertname"]
    instance = alert_data["instance"]
    severity = alert_data["severity"]
    summary = alert_data["summary"]
    cooldown_only = alert_data.get("cooldown_only", False)
    repo = bot.config.github_repo

    issue_num = None
    issue_url = None

    try:
        _post_thread(
            client, channel, thread_ts, ":mag: Checking for existing issues..."
        )

        existing = search_existing_issue(repo, alertname)

        if existing:
            issue_num, issue_url = existing
            _post_thread(
                client, channel, thread_ts, f":link: Found existing issue #{issue_num}"
            )

            now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            comment_on_issue(
                repo,
                issue_num,
                (
                    f"Alert still firing at {now}\n\n"
                    f"- **Instance:** {instance}\n"
                    f"- **Severity:** {severity}\n"
                    f"- **Summary:** {summary}"
                ),
            )
        else:
            _post_thread(client, channel, thread_ts, ":new: Opening new issue...")

            issue_num, issue_url = create_alert_issue(repo, alert_data)
            _post_thread(
                client, channel, thread_ts, f":memo: Created issue #{issue_num}"
            )

        if cooldown_only:
            _post_thread(
                client,
                channel,
                thread_ts,
                (
                    f":white_check_mark: Done (cooldown, skipped re-investigation) "
                    f"--- {issue_url}"
                ),
            )
            mark_processed(bot, alertname, instance)
            return

        _post_thread(client, channel, thread_ts, ":detective: Investigating...")

        past = []
        if bot.db:
            past = knowledge.get_past_investigations(
                bot.db, alertname, limit=bot.config.kb_context_limit
            )
            if past:
                _post_thread(
                    client,
                    channel,
                    thread_ts,
                    f":brain: Found {len(past)} previous investigation(s) for context",
                )

        findings = investigate_alert(bot, alert_data, past_investigations=past)

        _post_thread(client, channel, thread_ts, ":memo: Posting findings to issue...")

        if issue_num:
            comment_on_issue(
                repo, issue_num, f"## Auto-Investigation Findings\n\n{findings}"
            )

        if bot.db:
            knowledge.store_investigation(bot.db, alert_data, findings, issue_url)

        suggestion = _suggest_remediation(bot, alert_data, findings)
        if suggestion:
            _post_remediation_buttons(client, channel, thread_ts, alertname, suggestion)

        _post_thread(
            client, channel, thread_ts, f":white_check_mark: Done --- {issue_url}"
        )

        mark_processed(bot, alertname, instance)

    except Exception as e:
        log.exception("Error processing alert %s: %s", alertname, e)
        try:
            _post_thread(client, channel, thread_ts, f":x: Investigation failed: {e}")
        except Exception:
            pass


def alert_worker_loop(bot):
    log.info("Alert investigation worker started")
    while True:
        try:
            alert_data = bot.alert_queue.get()
            log.info(
                "Processing alert: %s (%s)",
                alert_data.get("alertname"),
                alert_data.get("instance"),
            )
            process_alert(bot, alert_data)
        except Exception as e:
            log.exception("Alert worker error: %s", e)
        finally:
            bot.alert_queue.task_done()


def fetch_alert_summary(cfg):
    try:
        req = urllib.request.Request(
            f"{cfg.alertmanager_url}/api/v2/alerts",
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            alerts = json.loads(resp.read().decode())
    except Exception as e:
        return f"(Alertmanager unreachable: {e})"

    active = [a for a in alerts if a.get("status", {}).get("state") == "active"]
    if not active:
        return "No alerts currently firing. All systems healthy."

    severity_order = {"critical": 0, "warning": 1}
    active.sort(
        key=lambda a: severity_order.get(a.get("labels", {}).get("severity", ""), 2)
    )

    crit_count = sum(
        1 for a in active if a.get("labels", {}).get("severity") == "critical"
    )
    warn_count = sum(
        1 for a in active if a.get("labels", {}).get("severity") == "warning"
    )
    lines = [
        f"{len(active)} alert(s) firing ({crit_count} critical, {warn_count} warning):"
    ]
    for a in active:
        labels = a.get("labels", {})
        annotations = a.get("annotations", {})
        sev = labels.get("severity", "unknown").upper()
        name = labels.get("alertname", "unknown")
        summary = annotations.get("summary", "no summary")
        cat = labels.get("category", "")
        cat_str = f" [{cat}]" if cat else ""
        lines.append(f"- [{sev}]{cat_str} {name}: {summary}")
    return "\n".join(lines)


def alert_poll_loop(bot):
    ticks = 0
    cleanup_interval = max(1, 3600 // bot.config.alert_poll_interval)
    while True:
        try:
            summary = fetch_alert_summary(bot.config)
            with bot.alert_summary_lock:
                bot.alert_summary = summary
        except Exception as e:
            log.error("Alert poll error: %s", e)

        ticks += 1
        if bot.db and ticks % cleanup_interval == 0:
            try:
                knowledge.cleanup(
                    bot.db, bot.config.kb_retention_days, bot.config.kb_max_rows
                )
            except Exception as e:
                log.error("Knowledge cleanup error: %s", e)

        time.sleep(bot.config.alert_poll_interval)
