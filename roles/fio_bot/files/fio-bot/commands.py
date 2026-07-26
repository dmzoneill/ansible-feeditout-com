"""Slash command handlers for /fio."""

import logging
import re

import audit
import knowledge
from executor import execute_command
from llm import chat_with_llm

log = logging.getLogger("fio-bot")


def _run_and_respond(cmd, respond, title, cfg):
    output, exit_code = execute_command(cmd, cfg.command_timeout, cfg.max_output)
    code_indicator = "" if exit_code == 0 else f" (exit {exit_code})"
    respond(
        response_type="in_channel",
        text=f"*{title}*{code_indicator}\n```\n{output}\n```",
    )


def _cmd_status(bot, args, respond):
    _run_and_respond(
        "uptime; echo '---'; free -h; echo '---'; cat /proc/loadavg",
        respond,
        "System Status",
        bot.config,
    )


def _cmd_top(bot, args, respond):
    _run_and_respond(
        "ps aux --sort=-%cpu | head -11",
        respond,
        "Top Processes (CPU)",
        bot.config,
    )


def _cmd_uptime(bot, args, respond):
    _run_and_respond("uptime -p", respond, "Uptime", bot.config)


def _cmd_temp(bot, args, respond):
    _run_and_respond(
        "sensors 2>/dev/null | grep -E 'Core|temp'"
        " || cat /sys/class/thermal/thermal_zone*/temp 2>/dev/null"
        " | awk '{printf \"Zone: %.1f C\\n\", $1/1000}'"
        " || echo 'No temperature data available'",
        respond,
        "Temperatures",
        bot.config,
    )


def _cmd_memory(bot, args, respond):
    _run_and_respond(
        "free -h && echo '---'"
        " && vmstat -s | head -10"
        " || echo 'vmstat not available'",
        respond,
        "Memory",
        bot.config,
    )


def _cmd_journal(bot, args, respond):
    parts = args.split() if args else []
    unit = None
    lines = 20
    for p in parts:
        if p.isdigit():
            lines = min(int(p), 100)
        elif not unit:
            unit = p
    cmd = f"journalctl -p err -b --no-pager -n {lines}"
    if unit:
        cmd += f" -u {_safe_arg(unit)}"
    title = f"Journal Errors ({unit or 'system'})"
    _run_and_respond(cmd, respond, title, bot.config)


def _cmd_disk(bot, args, respond):
    _run_and_respond(
        "df -h -x devtmpfs -x tmpfs 2>/dev/null || df -h",
        respond,
        "Disk Usage",
        bot.config,
    )


def _cmd_containers(bot, args, respond):
    _run_and_respond(
        "docker ps --format 'table {{.Names}}\\t{{.Status}}\\t{{.Ports}}'",
        respond,
        "Containers",
        bot.config,
    )


def _cmd_logs(bot, args, respond):
    parts = args.split() if args else []
    if not parts:
        respond(
            response_type="in_channel",
            text="Usage: `/fio logs <container> [lines]` (e.g., `/fio logs wordpress 50`)",
        )
        return
    name = _safe_arg(parts[0])
    lines = 30
    if len(parts) > 1 and parts[1].isdigit():
        lines = min(int(parts[1]), 200)
    _run_and_respond(
        f"docker logs --tail {lines} {name} 2>&1",
        respond,
        f"Logs -- {name} (last {lines})",
        bot.config,
    )


def _cmd_inspect(bot, args, respond):
    if not args or not args.strip():
        respond(
            response_type="in_channel",
            text="Usage: `/fio inspect <container>`",
        )
        return
    name = _safe_arg(args.split()[0])
    fmt = "Name: {{.Name}}\\nImage: {{.Config.Image}}\\nState: {{.State.Status}}\\nCreated: {{.Created}}\\nPorts: {{.HostConfig.PortBindings}}"
    _run_and_respond(
        f"docker inspect {name} --format '{fmt}'",
        respond,
        f"Inspect -- {name}",
        bot.config,
    )


def _cmd_images(bot, args, respond):
    _run_and_respond(
        "docker images --format 'table {{.Repository}}\\t{{.Tag}}\\t{{.Size}}\\t{{.CreatedSince}}'",
        respond,
        "Container Images",
        bot.config,
    )


def _cmd_restart_container(bot, args, respond):
    if not args or not args.strip():
        respond(
            response_type="in_channel",
            text="Usage: `/fio restart-container <name>`",
        )
        return
    name = _safe_arg(args.split()[0])
    _run_and_respond(f"docker restart {name}", respond, f"Restart -- {name}", bot.config)


def _cmd_stop_container(bot, args, respond):
    if not args or not args.strip():
        respond(
            response_type="in_channel",
            text="Usage: `/fio stop-container <name>`",
        )
        return
    name = _safe_arg(args.split()[0])
    _run_and_respond(f"docker stop {name}", respond, f"Stop -- {name}", bot.config)


def _cmd_start_container(bot, args, respond):
    if not args or not args.strip():
        respond(
            response_type="in_channel",
            text="Usage: `/fio start-container <name>`",
        )
        return
    name = _safe_arg(args.split()[0])
    _run_and_respond(f"docker start {name}", respond, f"Start -- {name}", bot.config)


# --- Monitoring ---


def _cmd_alerts(bot, args, respond):
    with bot.alert_summary_lock:
        summary = bot.alert_summary
    if not summary:
        summary = "No alert data available yet."
    respond(response_type="in_channel", text=f"*Alerts*\n{summary}")


# --- Security ---


def _cmd_banned(bot, args, respond):
    _run_and_respond(
        "fail2ban-client status sshd 2>/dev/null || echo 'fail2ban not running'",
        respond,
        "Banned IPs (sshd)",
        bot.config,
    )


def _cmd_unban(bot, args, respond):
    if not args or not args.strip():
        respond(
            response_type="in_channel",
            text="Usage: `/fio unban <ip>`",
        )
        return
    ip = _safe_arg(args.split()[0])
    _run_and_respond(
        f"fail2ban-client set sshd unbanip {ip} 2>&1",
        respond,
        f"Unban -- {ip}",
        bot.config,
    )


def _cmd_audit(bot, args, respond):
    _run_and_respond(
        "ausearch -ts recent -m USER_AUTH,USER_LOGIN --interpret 2>/dev/null"
        " | tail -20 || echo 'No recent auth events'",
        respond,
        "Recent Auth Events",
        bot.config,
    )


def _cmd_firewall(bot, args, respond):
    _run_and_respond(
        "iptables -L ANSIBLE_INPUT -n 2>/dev/null || echo 'ANSIBLE_INPUT chain not found'",
        respond,
        "Firewall Rules (ANSIBLE_INPUT)",
        bot.config,
    )


def _cmd_fail2ban(bot, args, respond):
    _run_and_respond(
        "fail2ban-client status 2>/dev/null || echo 'fail2ban not running'",
        respond,
        "Fail2Ban Status",
        bot.config,
    )


# --- Services ---


def _cmd_services(bot, args, respond):
    output, _ = execute_command(
        "systemctl list-units --state=failed --no-pager --no-legend",
        bot.config.command_timeout,
        bot.config.max_output,
    )
    if not output.strip() or output.strip() == "(no output)":
        respond(
            response_type="in_channel",
            text="*Failed Services*\nNo failed units :white_check_mark:",
        )
    else:
        respond(
            response_type="in_channel", text=f"*Failed Services*\n```\n{output}\n```"
        )


def _cmd_service(bot, args, respond):
    if not args or not args.strip():
        respond(
            response_type="in_channel",
            text="Usage: `/fio service <name>` (e.g., `/fio service fio-bot`)",
        )
        return
    name = _safe_arg(args.split()[0])
    _run_and_respond(
        f"systemctl status {name} --no-pager -l 2>&1 | head -20",
        respond,
        f"Service -- {name}",
        bot.config,
    )


# --- Network ---


def _cmd_network(bot, args, respond):
    _run_and_respond("ip addr show", respond, "Network Interfaces", bot.config)


def _cmd_ports(bot, args, respond):
    _run_and_respond("ss -tlnp", respond, "Listening Ports", bot.config)


def _cmd_dns(bot, args, respond):
    _run_and_respond(
        "cat /etc/resolv.conf",
        respond,
        "DNS Configuration",
        bot.config,
    )


def _cmd_ntp(bot, args, respond):
    _run_and_respond(
        "chronyc tracking 2>/dev/null"
        " || timedatectl show --property=NTPSynchronized --value",
        respond,
        "NTP Sync",
        bot.config,
    )


# --- Updates & maintenance ---


def _cmd_updates(bot, args, respond):
    _run_and_respond(
        "apt list --upgradable 2>/dev/null | head -30"
        " || echo 'System up to date'",
        respond,
        "Pending Updates",
        bot.config,
    )


# --- Infrastructure ---


def _cmd_certs(bot, args, respond):
    _run_and_respond(
        "certbot certificates 2>/dev/null || echo 'certbot not installed'",
        respond,
        "SSL Certificates",
        bot.config,
    )


def _cmd_postfix(bot, args, respond):
    _run_and_respond(
        "postqueue -p 2>/dev/null || echo 'postfix not running'",
        respond,
        "Postfix Mail Queue",
        bot.config,
    )


def _cmd_issues(bot, args, respond):
    _run_and_respond(
        f"gh issue list --repo {bot.config.github_repo} --label alert --state open",
        respond,
        "Open Alert Issues",
        bot.config,
    )


# --- Web stack ---


def _cmd_apache(bot, args, respond):
    _run_and_respond(
        "apachectl -S 2>&1 || echo 'Apache not running'",
        respond,
        "Apache VHost Summary",
        bot.config,
    )


def _cmd_mysql(bot, args, respond):
    _run_and_respond(
        "mysqladmin status 2>/dev/null || echo 'MySQL not running'",
        respond,
        "MySQL Status",
        bot.config,
    )


def _cmd_php_fpm(bot, args, respond):
    _run_and_respond(
        "systemctl status php8.4-fpm --no-pager -l 2>&1 | head -15"
        " || echo 'php8.4-fpm not found'",
        respond,
        "PHP-FPM Status",
        bot.config,
    )


def _cmd_domains(bot, args, respond):
    _run_and_respond(
        "apachectl -S 2>&1 | grep -E 'port|namevhost' || echo 'No domains configured'",
        respond,
        "Configured Domains",
        bot.config,
    )


def _cmd_redis(bot, args, respond):
    _run_and_respond(
        "redis-cli -a $REDIS_AUTH info server 2>/dev/null | head -20"
        " || echo 'Redis not running'",
        respond,
        "Redis Server Info",
        bot.config,
    )


def _cmd_ssl(bot, args, respond):
    _run_and_respond(
        "openssl x509 -in /etc/letsencrypt/live/fio.ie/cert.pem -noout -dates 2>/dev/null"
        " || echo 'SSL cert not found'",
        respond,
        "SSL Certificate Dates (fio.ie)",
        bot.config,
    )


def _cmd_clamav(bot, args, respond):
    _run_and_respond(
        "systemctl status clamav-freshclam --no-pager -l 2>&1 | head -10"
        " && echo '---'"
        " && ls -lt /var/log/clamav/ 2>/dev/null | head -5"
        " || echo 'ClamAV not installed'",
        respond,
        "ClamAV",
        bot.config,
    )


def _cmd_aide(bot, args, respond):
    _run_and_respond(
        "ls -lt /var/log/aide/ 2>/dev/null | head -5"
        " && echo '---'"
        " && tail -20 /var/log/aide/aide.log 2>/dev/null"
        " || echo 'No AIDE check results found'",
        respond,
        "AIDE Integrity Check",
        bot.config,
    )


# --- Bot management ---


def _cmd_personality(bot, args, respond):
    with bot.personality_lock:
        p = bot.personality
    if p:
        respond(response_type="in_channel", text=f"*Current Personality*\n> {p}")
    else:
        respond(
            response_type="in_channel",
            text="*Current Personality*\nDefault (no custom personality set)",
        )


def _cmd_ask(bot, args, respond, command):
    if not args or not args.strip():
        respond(
            response_type="in_channel",
            text="Usage: `/fio ask <question>` (e.g., `/fio ask what is the current load?`)",
        )
        return
    respond(response_type="in_channel", text=":brain: Thinking...")
    thread_key = f"slash-{command['trigger_id']}"
    try:
        response = chat_with_llm(bot, thread_key, None, args)
        respond(response_type="in_channel", text=response, replace_original=False)
    except Exception as e:
        log.error("LLM error in /fio ask: %s", e)
        respond(response_type="in_channel", text=f"Error: {e}", replace_original=False)


def _cmd_version(bot, args, respond):
    _run_and_respond(
        f"git -C {bot.config.ansible_dir} log -1 --format='%h %s (%cr)'"
        " && echo '---'"
        " && systemctl show fio-bot --property=ActiveEnterTimestamp --value",
        respond,
        "Version",
        bot.config,
    )


def _cmd_pull(bot, args, respond):
    _run_and_respond(
        f"git -C {bot.config.ansible_dir} pull",
        respond,
        "Git Pull",
        bot.config,
    )


def _cmd_deploy(bot, args, respond):
    respond(response_type="in_channel", text=":rocket: Starting deploy...")
    cmd = (
        "systemd-run --no-block --unit=fio-bot-deploy"
        " --description='FIO Bot Deploy'"
        " /bin/bash -c 'cd /opt/ansible"
        " && ansible-pull -i inventories/hosts_local.ini"
        " -U https://github.com/dmzoneill/ansible-feeditout-com"
        " -d /opt/ansible"
        " --vault-password-file=/etc/ansible/.vault_pass.txt"
        " --tags fio_bot"
        " playbooks/reconcile.yml'"
    )
    output, exit_code = execute_command(cmd)
    if exit_code == 0:
        respond(
            response_type="in_channel",
            text=(
                "Deploy started. Bot will restart shortly.\n"
                "Check `/fio deploy-log` for output."
            ),
            replace_original=False,
        )
    else:
        respond(
            response_type="in_channel",
            text=f"Deploy failed to start:\n```\n{output}\n```",
            replace_original=False,
        )


def _cmd_deploy_log(bot, args, respond):
    _run_and_respond(
        "journalctl -u fio-bot-deploy --no-pager -n 30 2>&1"
        " || echo 'No deploy logs found'",
        respond,
        "Deploy Log",
        bot.config,
    )


def _cmd_restart(bot, args, respond):
    respond(
        response_type="in_channel",
        text=":arrows_counterclockwise: Restarting fio-bot...",
    )
    execute_command("systemd-run --on-active=3s /bin/systemctl restart fio-bot")


# --- Knowledge base ---


def _cmd_knowledge(bot, args, respond):
    if not bot.db:
        respond(response_type="in_channel", text="Knowledge base not initialized.")
        return
    if args and args.strip():
        alertname = args.strip()
        past = knowledge.get_past_investigations(bot.db, alertname, limit=10)
        if not past:
            respond(
                response_type="in_channel",
                text=f"*Knowledge*\nNo investigations found for `{alertname}`.",
            )
            return
        lines = [f"*Investigations for `{alertname}`* ({len(past)} found)\n"]
        for inv in past:
            findings = inv.get("findings", "")
            if len(findings) > 200:
                findings = findings[:200] + "..."
            lines.append(
                f"*{inv['created_at']}* -- {inv.get('severity', '?')}"
                f" / {inv.get('instance', '?')}"
            )
            lines.append(f"  {findings}\n")
        respond(response_type="in_channel", text="\n".join(lines))
    else:
        stats = knowledge.get_stats(bot.db)
        lines = [
            "*Knowledge Base*",
            f"  Investigations: {stats['investigations']}",
            f"  Notes: {stats['notes']}",
            f"  Oldest: {stats['oldest'] or 'n/a'}",
            f"  Newest: {stats['newest'] or 'n/a'}",
        ]
        if stats["top_alerts"]:
            lines.append("  *Top alerts:*")
            for name, cnt in stats["top_alerts"]:
                lines.append(f"    `{name}` -- {cnt} investigation(s)")
        respond(response_type="in_channel", text="\n".join(lines))


def _cmd_note(bot, args, respond, command):
    if not bot.db:
        respond(response_type="in_channel", text="Knowledge base not initialized.")
        return
    parts = args.split(None, 1) if args else []
    if len(parts) < 2:
        respond(
            response_type="in_channel",
            text="Usage: `/fio note <topic> <text>` (e.g., `/fio note HighCPU ignore during backup window`)",
        )
        return
    topic = parts[0]
    note_text = parts[1]
    author = command.get("user_name", "unknown")
    knowledge.store_note(bot.db, topic, note_text, author)
    respond(
        response_type="in_channel",
        text=f":memo: Note saved for `{topic}`:\n> {note_text}",
    )


def _cmd_notes(bot, args, respond):
    if not bot.db:
        respond(response_type="in_channel", text="Knowledge base not initialized.")
        return
    topic = args.strip() if args else None
    notes = knowledge.get_notes(bot.db, topic=topic, limit=10)
    if not notes:
        msg = "No notes found."
        if topic:
            msg = f"No notes found for `{topic}`."
        respond(response_type="in_channel", text=f"*Notes*\n{msg}")
        return
    title = f"*Notes for `{topic}`*" if topic else "*All Notes*"
    lines = [f"{title} ({len(notes)} found)\n"]
    for n in notes:
        lines.append(
            f"*{n['created_at']}* -- `{n['topic']}` (by {n.get('author', '?')})"
        )
        lines.append(f"  {n['note']}\n")
    respond(response_type="in_channel", text="\n".join(lines))


# --- Command registry ---

COMMANDS = {
    "status": {
        "desc": "System overview (uptime, load, memory)",
        "usage": "/fio status",
    },
    "top": {"desc": "Top 10 processes by CPU", "usage": "/fio top"},
    "uptime": {"desc": "Server uptime", "usage": "/fio uptime"},
    "temp": {"desc": "CPU temperature", "usage": "/fio temp"},
    "memory": {"desc": "Memory usage details", "usage": "/fio memory"},
    "journal": {
        "desc": "Recent journal errors",
        "usage": "/fio journal [unit] [lines]",
    },
    "disk": {"desc": "Filesystem usage", "usage": "/fio disk"},
    "containers": {"desc": "List running Docker containers", "usage": "/fio containers"},
    "logs": {"desc": "Tail container logs", "usage": "/fio logs <name> [lines]"},
    "inspect": {"desc": "Container details", "usage": "/fio inspect <name>"},
    "images": {"desc": "List Docker images", "usage": "/fio images"},
    "restart-container": {
        "desc": "Restart a container",
        "usage": "/fio restart-container <name>",
    },
    "stop-container": {
        "desc": "Stop a container",
        "usage": "/fio stop-container <name>",
    },
    "start-container": {
        "desc": "Start a container",
        "usage": "/fio start-container <name>",
    },
    "alerts": {"desc": "Current firing alerts", "usage": "/fio alerts"},
    "banned": {"desc": "Fail2ban banned IPs (sshd)", "usage": "/fio banned"},
    "unban": {"desc": "Unban an IP from sshd", "usage": "/fio unban <ip>"},
    "audit": {"desc": "Recent auth/login events", "usage": "/fio audit"},
    "firewall": {
        "desc": "Firewall rules (ANSIBLE_INPUT chain)",
        "usage": "/fio firewall",
    },
    "fail2ban": {"desc": "Fail2Ban jail status", "usage": "/fio fail2ban"},
    "services": {"desc": "List failed systemd units", "usage": "/fio services"},
    "service": {"desc": "Status of a systemd unit", "usage": "/fio service <name>"},
    "network": {"desc": "Network interfaces and IPs", "usage": "/fio network"},
    "ports": {"desc": "Listening TCP ports", "usage": "/fio ports"},
    "dns": {"desc": "DNS resolver configuration", "usage": "/fio dns"},
    "ntp": {"desc": "NTP sync status", "usage": "/fio ntp"},
    "updates": {"desc": "Pending apt updates", "usage": "/fio updates"},
    "certs": {"desc": "SSL certificate status", "usage": "/fio certs"},
    "postfix": {"desc": "Postfix mail queue", "usage": "/fio postfix"},
    "issues": {"desc": "Open alert GitHub issues", "usage": "/fio issues"},
    "apache": {"desc": "Apache VHost summary", "usage": "/fio apache"},
    "mysql": {"desc": "MySQL server status", "usage": "/fio mysql"},
    "php-fpm": {"desc": "PHP-FPM service status", "usage": "/fio php-fpm"},
    "domains": {"desc": "List configured Apache domains", "usage": "/fio domains"},
    "redis": {"desc": "Redis server info", "usage": "/fio redis"},
    "ssl": {"desc": "SSL cert expiry dates (fio.ie)", "usage": "/fio ssl"},
    "clamav": {"desc": "ClamAV antivirus status", "usage": "/fio clamav"},
    "aide": {"desc": "AIDE integrity check results", "usage": "/fio aide"},
    "personality": {
        "desc": "Show current bot personality",
        "usage": "/fio personality",
    },
    "ask": {"desc": "Ask the LLM a question", "usage": "/fio ask <question>"},
    "version": {"desc": "Current git commit and uptime", "usage": "/fio version"},
    "pull": {"desc": "Git pull in the Ansible repo", "usage": "/fio pull"},
    "deploy": {
        "desc": "Deploy fio-bot via ansible-pull",
        "usage": "/fio deploy",
    },
    "deploy-log": {"desc": "Show output from last deploy", "usage": "/fio deploy-log"},
    "restart": {"desc": "Restart the bot service", "usage": "/fio restart"},
    "knowledge": {
        "desc": "Knowledge base stats or alert history",
        "usage": "/fio knowledge [alertname]",
    },
    "note": {"desc": "Add a knowledge note", "usage": "/fio note <topic> <text>"},
    "notes": {"desc": "List knowledge notes", "usage": "/fio notes [topic]"},
    "help": {"desc": "List all commands", "usage": "/fio help"},
}

HANDLERS = {
    "status": _cmd_status,
    "top": _cmd_top,
    "uptime": _cmd_uptime,
    "temp": _cmd_temp,
    "memory": _cmd_memory,
    "journal": _cmd_journal,
    "disk": _cmd_disk,
    "containers": _cmd_containers,
    "logs": _cmd_logs,
    "inspect": _cmd_inspect,
    "images": _cmd_images,
    "restart-container": _cmd_restart_container,
    "stop-container": _cmd_stop_container,
    "start-container": _cmd_start_container,
    "alerts": _cmd_alerts,
    "banned": _cmd_banned,
    "unban": _cmd_unban,
    "audit": _cmd_audit,
    "firewall": _cmd_firewall,
    "fail2ban": _cmd_fail2ban,
    "services": _cmd_services,
    "service": _cmd_service,
    "network": _cmd_network,
    "ports": _cmd_ports,
    "dns": _cmd_dns,
    "ntp": _cmd_ntp,
    "updates": _cmd_updates,
    "certs": _cmd_certs,
    "postfix": _cmd_postfix,
    "issues": _cmd_issues,
    "apache": _cmd_apache,
    "mysql": _cmd_mysql,
    "php-fpm": _cmd_php_fpm,
    "domains": _cmd_domains,
    "redis": _cmd_redis,
    "ssl": _cmd_ssl,
    "clamav": _cmd_clamav,
    "aide": _cmd_aide,
    "personality": _cmd_personality,
    "ask": _cmd_ask,
    "version": _cmd_version,
    "pull": _cmd_pull,
    "deploy": _cmd_deploy,
    "deploy-log": _cmd_deploy_log,
    "restart": _cmd_restart,
    "knowledge": _cmd_knowledge,
    "note": _cmd_note,
    "notes": _cmd_notes,
}


def _cmd_help(bot, args, respond):
    lines = ["*`/fio` Commands*\n"]
    sections = {
        "System": ["status", "top", "uptime", "temp", "memory", "journal"],
        "Storage": ["disk"],
        "Containers": [
            "containers",
            "logs",
            "inspect",
            "images",
            "restart-container",
            "stop-container",
            "start-container",
        ],
        "Monitoring": ["alerts"],
        "Security": ["banned", "unban", "audit", "firewall", "fail2ban"],
        "Services": ["services", "service"],
        "Network": ["network", "ports", "dns", "ntp"],
        "Updates": ["updates"],
        "Web Stack": ["apache", "mysql", "php-fpm", "domains", "redis"],
        "Security Scanning": ["clamav", "aide"],
        "Infrastructure": ["certs", "ssl", "postfix"],
        "GitHub": ["issues"],
        "Knowledge": ["knowledge", "note", "notes"],
        "Bot": [
            "personality",
            "ask",
            "version",
            "pull",
            "deploy",
            "deploy-log",
            "restart",
            "help",
        ],
    }
    for section, cmds in sections.items():
        lines.append(f"*{section}*")
        for name in cmds:
            meta = COMMANDS[name]
            lines.append(f"  `{meta['usage']}` -- {meta['desc']}")
        lines.append("")
    respond(response_type="in_channel", text="\n".join(lines))


def _safe_arg(value):
    return re.sub(r"[^a-zA-Z0-9._\-/]", "", value)


def register(bot):

    @bot.app.command("/fio")
    def handle_fio_command(ack, command, respond):
        ack()

        text = (command.get("text") or "").strip()
        parts = text.split(None, 1)
        subcommand = parts[0].lower() if parts else "help"
        args = parts[1] if len(parts) > 1 else ""

        log.info(
            "SLASH /fio %s (args=%s) from %s",
            subcommand,
            args[:50],
            command.get("user_name"),
        )

        audit.log_command(bot, command.get("user_name", "?"), subcommand, args)

        if subcommand == "help":
            _cmd_help(bot, args, respond)
            return

        handler = HANDLERS.get(subcommand)
        if not handler:
            respond(
                response_type="in_channel",
                text=f"Unknown command: `{subcommand}`. Type `/fio help` for available commands.",
            )
            return

        try:
            if subcommand in ("ask", "note"):
                handler(bot, args, respond, command)
            else:
                handler(bot, args, respond)
        except Exception as e:
            log.exception("Error in /fio %s: %s", subcommand, e)
            respond(
                response_type="in_channel", text=f"Error running `{subcommand}`: {e}"
            )
