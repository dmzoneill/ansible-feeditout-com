"""GitHub issue management via the gh CLI."""

import json
import logging
import re
from datetime import datetime, timezone

from executor import execute_command

log = logging.getLogger("fio-bot")


def search_existing_issue(repo, alertname):
    safe_name = alertname.replace('"', '\\"')
    cmd = (
        f"gh issue list --repo {repo} --state open "
        f'--search "[ALERT] {safe_name}" --json number,url --limit 1'
    )
    output, exit_code = execute_command(cmd)
    if exit_code != 0 or not output.strip() or output.strip() == "[]":
        return None
    try:
        issues = json.loads(output.strip())
        if issues:
            return (issues[0]["number"], issues[0]["url"])
    except (json.JSONDecodeError, KeyError, IndexError):
        pass
    return None


def create_alert_issue(repo, alert_info):
    title = f"[ALERT] {alert_info['alertname']} — {alert_info['summary']}"
    if len(title) > 256:
        title = title[:253] + "..."

    body = (
        f"## Alert Details\n\n"
        f"- **Alert:** {alert_info['alertname']}\n"
        f"- **Status:** FIRING\n"
        f"- **Severity:** {alert_info['severity']}\n"
        f"- **Instance:** {alert_info['instance']}\n"
        f"- **Category:** {alert_info['category']}\n"
        f"- **Summary:** {alert_info['summary']}\n"
    )
    if alert_info.get("description"):
        body += f"\n{alert_info['description']}\n"
    body += (
        f"\n---\n*Auto-created by FIO Bot at "
        f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}*\n"
    )

    labels = f"alert,severity:{alert_info['severity']}"
    if alert_info.get("category") and alert_info["category"] != "unknown":
        labels += f",category:{alert_info['category']}"

    safe_title = title.replace("'", "'\\''")
    safe_body = body.replace("'", "'\\''")

    cmd = (
        f"gh issue create --repo {repo} "
        f"--title '{safe_title}' "
        f"--body '{safe_body}' "
        f"--label '{labels}'"
    )
    output, exit_code = execute_command(cmd)

    url_match = re.search(r"(https://github\.com/\S+/issues/\d+)", output)
    if url_match:
        url = url_match.group(1)
        num_match = re.search(r"/issues/(\d+)", url)
        issue_num = int(num_match.group(1)) if num_match else 0
        return (issue_num, url)

    log.warning("Could not parse issue URL from gh output: %s", output)
    return (0, f"https://github.com/{repo}/issues")


def comment_on_issue(repo, issue_number, comment):
    safe_comment = comment.replace("'", "'\\''")
    cmd = f"gh issue comment {issue_number} --repo {repo} " f"--body '{safe_comment}'"
    output, exit_code = execute_command(cmd)
    if exit_code != 0:
        log.error("Failed to comment on issue #%s: %s", issue_number, output)


def ensure_labels(repo, alert_channels):
    labels = [
        ("alert", "d73a4a", "Auto-created alert investigation"),
        ("severity:critical", "dc3545", "Critical severity alert"),
        ("severity:warning", "ffc107", "Warning severity alert"),
    ]
    for cat in alert_channels:
        labels.append((f"category:{cat}", "0075ca", f"Alert category: {cat}"))

    for name, color, desc in labels:
        execute_command(
            f'gh label create "{name}" --color "{color}" '
            f'--description "{desc}" --repo {repo} --force'
        )
