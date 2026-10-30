"""Alert parsing, investigation, polling, and worker loop."""

import importlib
import json
import logging
import re
import sqlite3
import time
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from functools import partial

import knowledge
from config import alert_investigation_prompt
from executor import execute_command
from github import comment_on_issue, create_alert_issue, search_existing_issue
from llm import extract_commands, strip_actions

log = logging.getLogger("fio-bot")

# Both SDKs are runtime dependencies of the bot; loaded by name so this
# module's import block is ordered the same way for isort, ruff and pylint.
SlackApiError = importlib.import_module("slack_sdk.errors").SlackApiError
OpenAIError = importlib.import_module("openai").OpenAIError

# Slack API errors plus network-level failures (connection resets, timeouts).
SLACK_ERRORS = (SlackApiError, OSError)
# Everything processing one alert can reasonably raise: LLM, Slack, the
# knowledge DB, gh/subprocess I/O, and malformed alert or API data.
ALERT_ERRORS = (
    OpenAIError,
    SlackApiError,
    sqlite3.Error,
    OSError,
    ValueError,
    KeyError,
)

ALERT_KEYWORDS = re.compile(
    r"FIRING|UNHEALTHY|CRITICAL|DEGRADED|DOWN|FAILED|ERROR|ALERT",
    re.IGNORECASE,
)

REMEDIATION_PROMPT = (
    "Based on the investigation findings, suggest a single shell command"
    " that would fix or mitigate this alert.\n"
    "Only suggest commands that are safe and reversible"
    " (restart a service, clear a cache, kill a process).\n"
    "Never suggest destructive commands (rm -rf, reboot).\n"
    "If no remediation is appropriate, respond with exactly: none\n"
    "Respond with ONLY the command, nothing else."
)
REMEDIATION_REQUEST = "Alert: {alertname}\nSummary: {summary}\nFindings:\n{findings}"
INVESTIGATE_REQUEST = "Investigate this alert: {alertname} --- {summary}"
HISTORY_ENTRY = "\n[{created_at}] Severity: {severity}, Instance: {instance}"
_HISTORY_USE = "\nUse this context to inform your investigation."
HISTORY_FOOTER = _HISTORY_USE + " Note patterns or recurring issues."
DONE_COOLDOWN = ":white_check_mark: Done (cooldown, skipped re-investigation) --- {url}"
SUMMARY_HEADER = "{total} alert(s) firing ({critical} critical, {warning} warning):"
NO_REMEDIATION = ("none", "no remediation needed", "n/a", "")

HISTORY_FINDINGS_LIMIT = 500
SEVERITY_ORDER = {"critical": 0, "warning": 1}


def _run_guarded(what, func, *args):
    """Run one iteration of a daemon loop; log, never propagate, any error.

    The worker and poll loops run in daemon threads for the bot's lifetime.
    An unexpected exception would silently kill the thread and stop all
    alert handling, so this is the one deliberate catch-all.
    """
    try:
        func(*args)
    except Exception:  # pylint: disable=broad-exception-caught
        log.exception("%s error", what)


def _extract_field(text, field_name):
    """Value of a '*Field:* value' or 'Field: value' line, or None."""
    match = re.search(rf"\*{field_name}:\*\s*(.+)", text)
    if match:
        return match.group(1).strip()
    match = re.search(rf"(?:^|\n)\s*\*?{field_name}:\*?\s*(.+)", text, re.IGNORECASE)
    return match.group(1).strip() if match else None


def _first_field(text, *field_names):
    """Value of the first of field_names present in text, or None."""
    for name in field_names:
        value = _extract_field(text, name)
        if value:
            return value
    return None


def _collect_text(event):
    """All human-readable text of a Slack alert event, one part per line."""
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
            parts.extend(field.get("text", "") for field in block.get("fields", []))
    if event.get("text"):
        parts.append(event["text"])
    return "\n".join(parts)


def _alert_name(event, full_text):
    """Alert name from the FIRING title, attachment, header, or first line."""
    title_match = re.search(r"\[FIRING:\d+\]\s+(.+)", full_text)
    if title_match:
        return re.sub(r"^\*?Alert:\*?\s*", "", title_match.group(1).strip()).strip()
    for att in event.get("attachments", []):
        t = att.get("title", "")
        if t:
            return t.strip()
    for block in event.get("blocks", []):
        if block.get("type") == "header":
            return block.get("text", {}).get("text", "").strip()
    first_line = full_text.split("\n", maxsplit=1)[0].strip()
    return first_line[:120] if first_line else "UnknownAlert"


def _description(full_text, alertname):
    """Free-text lines of the alert that are not 'Field: value' or the name."""
    lines = []
    for raw in full_text.split("\n"):
        line = raw.strip()
        if line and not re.match(r"^\*?\w+:\*?\s", line) and line != alertname:
            lines.append(line)
    return "\n".join(lines)


def parse_alert_from_event(event, channel_id_to_category):
    """Alert info dict for a Slack alert message, or None if not an alert."""
    full_text = _collect_text(event)
    if not full_text or not ALERT_KEYWORDS.search(full_text):
        return None

    alertname = _alert_name(event, full_text)
    severity = _extract_field(full_text, "Severity") or "unknown"
    instance = _first_field(full_text, "Instance", "Host") or "unknown"
    summary = _first_field(full_text, "Summary", "Event") or ""
    resolved = re.search(r"RESOLVED|RECOVERED", full_text, re.IGNORECASE)

    return {
        "alertname": alertname,
        "severity": severity.lower(),
        "instance": instance,
        "summary": summary,
        "description": _description(full_text, alertname),
        "category": channel_id_to_category.get(event.get("channel", ""), "unknown"),
        "status": "RESOLVED" if resolved else "FIRING",
    }


def is_on_cooldown(bot, alertname, instance):
    """True if this alert/instance was processed within the cooldown window."""
    key = (alertname, instance)
    with bot.alert_cooldowns_lock:
        last_seen = bot.alert_cooldowns.get(key, 0)
        return (time.time() - last_seen) < bot.config.alert_cooldown_seconds


def mark_processed(bot, alertname, instance):
    """Start the cooldown window for this alert/instance."""
    key = (alertname, instance)
    with bot.alert_cooldowns_lock:
        bot.alert_cooldowns[key] = time.time()


def maybe_enqueue_alert(bot, event, channel, client):
    """Queue a new (top-level, firing) alert message for investigation."""
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
    """Reply in the alert thread; Slack failures are logged, not raised."""
    try:
        client.chat_postMessage(channel=channel, thread_ts=thread_ts, text=text)
    except SLACK_ERRORS as e:
        log.error("Failed to post thread reply: %s", e)


def _suggest_remediation(bot, alert_info, findings):
    """One safe shell command the LLM suggests as a fix, or None."""
    user_content = REMEDIATION_REQUEST.format(
        alertname=alert_info["alertname"],
        summary=alert_info.get("summary", ""),
        findings=findings,
    )
    try:
        response = bot.llm.chat.completions.create(
            model=bot.config.model,
            messages=[
                {"role": "system", "content": REMEDIATION_PROMPT},
                {"role": "user", "content": user_content},
            ],
            max_tokens=256,
        )
    except OpenAIError as e:
        log.error("Remediation suggestion error: %s", e)
        return None
    suggestion = (response.choices[0].message.content or "").strip()
    if suggestion.lower() in NO_REMEDIATION:
        return None
    return suggestion


def _post_remediation_buttons(client, channel, thread_ts, alertname, suggestion):
    """Post the suggested command with Approve / Reject buttons."""
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
    except SLACK_ERRORS as e:
        log.error("Failed to post remediation buttons: %s", e)


def _history_context(past_investigations):
    """Prompt section summarising earlier investigations of this alert."""
    history_lines = ["\nPREVIOUS INVESTIGATIONS FOR THIS ALERT:"]
    for inv in past_investigations:
        entry = HISTORY_ENTRY.format(
            created_at=inv["created_at"],
            severity=inv.get("severity", "?"),
            instance=inv.get("instance", "?"),
        )
        history_lines.append(entry)
        findings = inv.get("findings", "")
        if len(findings) > HISTORY_FINDINGS_LIMIT:
            findings = findings[:HISTORY_FINDINGS_LIMIT] + "..."
        history_lines.append(f"Findings: {findings}")
    history_lines.append(HISTORY_FOOTER)
    return "\n".join(history_lines)


def _investigation_messages(cfg, alert_info, past_investigations):
    """Initial system + user messages for an alert investigation."""
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
        prompt += _history_context(past_investigations)
    request = INVESTIGATE_REQUEST.format(
        alertname=alert_info["alertname"],
        summary=alert_info["summary"],
    )
    return [
        {"role": "system", "content": prompt},
        {"role": "user", "content": request},
    ]


def _run_investigation_command(cfg, cmd, remaining):
    """Run one diagnostic command; return (finding text, LLM feedback)."""
    output, exit_code = execute_command(cmd, cfg.command_timeout, cfg.max_output)
    code = "" if exit_code == 0 else f" (exit {exit_code})"
    finding = f"**Command:** `{cmd}`{code}\n```\n{output}\n```"
    feedback = (
        f"[SYSTEM] Command `{cmd}` returned{code}:\n"
        f"```\n{output}\n```\n"
        f"You have {remaining} commands remaining. "
        "Run another diagnostic command or provide your final findings."
    )
    return finding, feedback


def investigate_alert(bot, alert_info, past_investigations=None):
    """Let the LLM run diagnostic commands and return its findings."""
    cfg = bot.config
    messages = _investigation_messages(cfg, alert_info, past_investigations)
    all_output_parts = []

    for round_num in range(cfg.alert_max_rounds + 1):
        try:
            response = bot.llm.chat.completions.create(
                model=cfg.model,
                messages=messages,
                max_tokens=2048,
            )
        except OpenAIError as e:
            log.error("LLM error during investigation: %s", e)
            all_output_parts.append(f"(LLM error: {e})")
            break

        reply = response.choices[0].message.content or ""
        commands = extract_commands(reply)
        display_text = strip_actions(reply)

        if not commands or round_num >= cfg.alert_max_rounds:
            if display_text:
                all_output_parts.append(display_text)
            if commands:
                all_output_parts.append("(Investigation round limit reached)")
            break

        messages.append({"role": "assistant", "content": reply})
        remaining = cfg.alert_max_rounds - round_num - 1
        finding, feedback = _run_investigation_command(cfg, commands[0], remaining)
        all_output_parts.append(finding)
        messages.append({"role": "user", "content": feedback})

    if not all_output_parts:
        return "(No findings produced)"
    return "\n\n".join(all_output_parts)


def _ensure_issue(repo, alert_data, post):
    """Comment on the alert's open GitHub issue or open one; (number, url)."""
    post(":mag: Checking for existing issues...")
    existing = search_existing_issue(repo, alert_data["alertname"])
    if not existing:
        post(":new: Opening new issue...")
        issue_num, issue_url = create_alert_issue(repo, alert_data)
        post(f":memo: Created issue #{issue_num}")
        return issue_num, issue_url

    issue_num, issue_url = existing
    post(f":link: Found existing issue #{issue_num}")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    comment_on_issue(
        repo,
        issue_num,
        (
            f"Alert still firing at {now}\n\n"
            f"- **Instance:** {alert_data['instance']}\n"
            f"- **Severity:** {alert_data['severity']}\n"
            f"- **Summary:** {alert_data['summary']}"
        ),
    )
    return issue_num, issue_url


def _investigate_and_report(bot, alert_data, issue, post):
    """Investigate, record findings on the issue and in the KB, suggest a fix."""
    issue_num, issue_url = issue
    alertname = alert_data["alertname"]
    post(":detective: Investigating...")

    past = []
    if bot.db:
        past = knowledge.get_past_investigations(
            bot.db,
            alertname,
            limit=bot.config.kb_context_limit,
        )
        if past:
            post(f":brain: Found {len(past)} previous investigation(s) for context")

    findings = investigate_alert(bot, alert_data, past_investigations=past)

    post(":memo: Posting findings to issue...")
    if issue_num:
        comment_on_issue(
            bot.config.github_repo,
            issue_num,
            f"## Auto-Investigation Findings\n\n{findings}",
        )
    if bot.db:
        knowledge.store_investigation(bot.db, alert_data, findings, issue_url)

    suggestion = _suggest_remediation(bot, alert_data, findings)
    if suggestion:
        _post_remediation_buttons(
            alert_data["client"],
            alert_data["channel"],
            alert_data["thread_ts"],
            alertname,
            suggestion,
        )


def process_alert(bot, alert_data):
    """Track the alert in GitHub, investigate it, and report in its thread."""
    alertname = alert_data["alertname"]

    post = partial(
        _post_thread,
        alert_data["client"],
        alert_data["channel"],
        alert_data["thread_ts"],
    )

    try:
        issue = _ensure_issue(bot.config.github_repo, alert_data, post)
        if alert_data.get("cooldown_only", False):
            post(DONE_COOLDOWN.format(url=issue[1]))
        else:
            _investigate_and_report(bot, alert_data, issue, post)
            post(f":white_check_mark: Done --- {issue[1]}")
        mark_processed(bot, alertname, alert_data["instance"])
    except ALERT_ERRORS as e:
        log.exception("Error processing alert %s", alertname)
        post(f":x: Investigation failed: {e}")


def _process_next_alert(bot):
    """Block for the next queued alert and process it."""
    alert_data = bot.alert_queue.get()
    try:
        log.info(
            "Processing alert: %s (%s)",
            alert_data.get("alertname"),
            alert_data.get("instance"),
        )
        process_alert(bot, alert_data)
    finally:
        bot.alert_queue.task_done()


def alert_worker_loop(bot):
    """Daemon loop: investigate queued alerts one at a time."""
    log.info("Alert investigation worker started")
    while True:
        _run_guarded("Alert worker", _process_next_alert, bot)


def _format_alert(alert):
    """One '- [SEV] [category] name: summary' line for an active alert."""
    labels = alert.get("labels", {})
    sev = labels.get("severity", "unknown").upper()
    name = labels.get("alertname", "unknown")
    summary = alert.get("annotations", {}).get("summary", "no summary")
    cat = labels.get("category", "")
    cat_str = f" [{cat}]" if cat else ""
    return f"- [{sev}]{cat_str} {name}: {summary}"


def _is_active(alert):
    """True if Alertmanager reports the alert as currently active."""
    return alert.get("status", {}).get("state") == "active"


def fetch_alert_summary(cfg):
    """Plain-text summary of the alerts currently firing in Alertmanager."""
    url = f"{cfg.alertmanager_url}/api/v2/alerts"
    if not url.startswith(("http://", "https://")):
        return f"(Alertmanager URL must be http(s), got {cfg.alertmanager_url!r})"
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        # Scheme is restricted to http(s) above, so no file:// or custom schemes.
        with urllib.request.urlopen(req, timeout=5) as resp:  # nosec B310
            alerts = json.loads(resp.read().decode())
    except (OSError, ValueError) as e:
        # URLError/HTTPError/timeouts are OSError; bad JSON is ValueError.
        return f"(Alertmanager unreachable: {e})"

    if not isinstance(alerts, list):
        return "(Alertmanager returned unexpected data)"
    active = [a for a in alerts if isinstance(a, dict) and _is_active(a)]
    if not active:
        return "No alerts currently firing. All systems healthy."

    def severity(alert):
        return alert.get("labels", {}).get("severity", "")

    active.sort(key=lambda a: SEVERITY_ORDER.get(severity(a), 2))
    counts = Counter(severity(a) for a in active)
    header = SUMMARY_HEADER.format(
        total=len(active),
        critical=counts["critical"],
        warning=counts["warning"],
    )
    return "\n".join([header, *map(_format_alert, active)])


def _poll_once(bot, cleanup_due):
    """Refresh the cached alert summary and, when due, prune the KB."""
    summary = fetch_alert_summary(bot.config)
    with bot.alert_summary_lock:
        bot.alert_summary = summary

    if bot.db and cleanup_due:
        try:
            knowledge.cleanup(
                bot.db,
                bot.config.kb_retention_days,
                bot.config.kb_max_rows,
            )
        except sqlite3.Error as e:
            log.error("Knowledge cleanup error: %s", e)


def alert_poll_loop(bot):
    """Daemon loop: poll Alertmanager and periodically clean up the KB."""
    ticks = 0
    cleanup_interval = max(1, 3600 // bot.config.alert_poll_interval)
    while True:
        ticks += 1
        _run_guarded("Alert poll", _poll_once, bot, ticks % cleanup_interval == 0)
        time.sleep(bot.config.alert_poll_interval)
