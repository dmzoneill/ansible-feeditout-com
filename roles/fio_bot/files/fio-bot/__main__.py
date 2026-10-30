#!/usr/bin/env python3
"""FIO Bot — FeedItOut ChatOps Slack bot."""

import importlib
import json
import logging
import queue
import sys
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import alerts
import audit
import commands
import config
import digest
import github
import idle
import knowledge
import personality as personality_mod
from executor import execute_command
from llm import chat_with_llm, fetch_thread_context

# Third-party SDKs are loaded by name so the import block above is ordered
# the same way for isort/ruff (which treat the sibling modules as
# third-party) and pylint (which treats them as first-party).
OpenAI = importlib.import_module("openai").OpenAI
OpenAIError = importlib.import_module("openai").OpenAIError
App = importlib.import_module("slack_bolt").App
_socket_mode = importlib.import_module("slack_bolt.adapter.socket_mode")
SocketModeHandler = _socket_mode.SocketModeHandler
SlackApiError = importlib.import_module("slack_sdk.errors").SlackApiError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("fio-bot")

# Slack API errors plus network-level failures (connection resets, timeouts).
SLACK_ERRORS = (SlackApiError, OSError)
# What answering a chat message can raise: Slack, the LLM, malformed data.
CHAT_ERRORS = (SlackApiError, OSError, OpenAIError, ValueError, KeyError)
# What a remediation button handler can raise: Slack or a malformed payload.
ACTION_ERRORS = (SlackApiError, OSError, ValueError, KeyError, IndexError, TypeError)

SLACK_MESSAGE_LIMIT = 3900
THREAD_CONTEXT_PROMPT = (
    "The user is asking from within a Slack thread. "
    "Here is the full thread conversation for context:\n"
    "---\n{context}\n---\n\n"
    "The user's request: {text}"
)


@dataclass
class Bot:  # pylint: disable=too-many-instance-attributes
    """Shared bot state passed to every handler and background thread.

    Each piece of shared state is paired with its own lock, so the
    attribute count is inherent to the design.
    """

    app: Any
    llm: Any
    config: config.Config
    bot_user_id: str = ""
    conversations: dict = field(default_factory=lambda: defaultdict(list))
    conversations_lock: threading.Lock = field(default_factory=threading.Lock)
    alert_summary: str = ""
    alert_summary_lock: threading.Lock = field(default_factory=threading.Lock)
    alert_queue: queue.Queue = field(default_factory=queue.Queue)
    alert_cooldowns: dict = field(default_factory=dict)
    alert_cooldowns_lock: threading.Lock = field(default_factory=threading.Lock)
    personality: str = ""
    personality_lock: threading.Lock = field(default_factory=threading.Lock)
    db: object = None


def _discover_alert_channels(bot):
    """Map #alerts / #alert-<category> channels the bot is in to categories."""
    try:
        result = bot.app.client.users_conversations(types="public_channel", limit=200)
    except SLACK_ERRORS as e:
        log.error("Failed to discover alert channels: %s", e)
        return
    alert_channels = {}
    for ch in result.get("channels", []):
        name = ch.get("name", "")
        if name == "alerts":
            alert_channels["general"] = ch["id"]
        elif name.startswith("alert-") and name != "alert-audit":
            category = name.removeprefix("alert-").replace("-", "_")
            alert_channels[category] = ch["id"]
    bot.config.alert_channels = alert_channels
    bot.config.alert_channel_ids = set(alert_channels.values())
    bot.config.channel_id_to_category = {v: k for k, v in alert_channels.items()}
    log.info(
        "Discovered %d alert channels: %s",
        len(alert_channels),
        ", ".join(sorted(alert_channels.keys())),
    )


def _get_thread_key(event):
    """Conversation key: the thread root's ts."""
    return event.get("thread_ts") or event.get("ts")


def _strip_mention(bot, text):
    """Remove the bot's own @-mention from a message."""
    if bot.bot_user_id:
        text = text.replace(f"<@{bot.bot_user_id}>", "").strip()
    return text


def _react(client, channel, ts, name, *, remove=False):
    """Add/remove a status reaction; reactions are cosmetic, so only log."""
    try:
        if remove:
            client.reactions_remove(channel=channel, name=name, timestamp=ts)
        else:
            client.reactions_add(channel=channel, name=name, timestamp=ts)
    except SLACK_ERRORS as e:
        log.debug("Reaction %s on %s failed: %s", name, ts, e)


def _say_chunked(say, text, thread_ts, channel):
    """Post text in a thread, split to stay under Slack's message limit."""
    for i in range(0, max(len(text), 1), SLACK_MESSAGE_LIMIT):
        say(
            text=text[i : i + SLACK_MESSAGE_LIMIT],
            thread_ts=thread_ts,
            channel=channel,
        )


def _respond(bot, client, say, event, text):
    """Answer a chat message in its thread (caller already added :eyes:)."""
    channel = event.get("channel")
    ts = event["ts"]
    thread_ts = event.get("thread_ts") or ts
    try:
        response = chat_with_llm(
            bot,
            _get_thread_key(event),
            thread_ts,
            text,
            channel=channel,
        )
        _say_chunked(say, response, thread_ts, channel)
        _react(client, channel, ts, "white_check_mark")
    except CHAT_ERRORS as e:
        log.exception("Error handling message")
        say(text=f"Error: {e}", thread_ts=thread_ts, channel=channel)
    _react(client, channel, ts, "eyes", remove=True)


def _handle_alert_channel_message(bot, event, client):
    """Queue top-level alert posts (human or bot) for investigation."""
    subtype = event.get("subtype", "")
    if subtype and subtype != "bot_message":
        return
    if event.get("thread_ts"):
        return
    alerts.maybe_enqueue_alert(bot, event, event.get("channel", ""), client)


def _handle_dm(bot, event, say, text):
    """A DM sets the bot personality; 'reset' restores the default."""
    channel = event.get("channel", "")
    user = event.get("user")
    text = _strip_mention(bot, text)
    try:
        if text.lower() == "reset":
            with bot.personality_lock:
                bot.personality = ""
            personality_mod.save(bot.config.personality_file, None)
            say(text="Personality reset to default FIO Bot.", channel=channel)
            log.info("Personality reset by %s", user)
            return
        saved = personality_mod.save(bot.config.personality_file, text) or ""
        with bot.personality_lock:
            bot.personality = saved
        say(text=f"Personality set to:\n> {text}", channel=channel)
        log.info("Personality set by %s: %s", user, text[:100])
    except (*SLACK_ERRORS, OSError) as e:
        log.exception("Error handling DM from %s", user)
        try:
            say(text=f"Error setting personality: {e}", channel=channel)
        except SLACK_ERRORS as say_error:
            log.error("Could not report DM error to %s: %s", user, say_error)


def _is_own_or_edit(bot, event):
    """True for edits/joins/etc. and for the bot's own messages."""
    if event.get("subtype"):
        return True
    return bool(bot.bot_user_id) and event.get("user") == bot.bot_user_id


def _register_handlers(bot):
    """Register the message and app_mention event handlers."""

    @bot.app.event("message")
    def handle_message(event, say, client):
        channel = event.get("channel", "")
        if channel in bot.config.alert_channel_ids:
            _handle_alert_channel_message(bot, event, client)
            return
        if _is_own_or_edit(bot, event):
            return
        text = event.get("text", "").strip()
        if not text:
            return
        if channel.startswith("D"):
            _handle_dm(bot, event, say, text)
            return
        if channel != bot.config.channel:
            return

        text = _strip_mention(bot, text)
        _react(client, channel, event["ts"], "eyes")
        log.info("MSG from %s: %s", event.get("user"), text[:100])
        audit.log_chat(bot, event.get("user", "unknown"), text)
        _respond(bot, client, say, event, text)

    @bot.app.event("app_mention")
    def handle_mention(event, say, client):
        channel = event.get("channel")
        if channel == bot.config.channel or event.get("subtype"):
            return
        text = _strip_mention(bot, event.get("text", "").strip())
        if not text:
            return

        _react(client, channel, event["ts"], "eyes")
        log.info("MENTION in %s from %s: %s", channel, event.get("user"), text[:100])
        if event.get("thread_ts"):
            context = fetch_thread_context(client, channel, event["thread_ts"])
            if context:
                text = THREAD_CONTEXT_PROMPT.format(context=context, text=text)
        _respond(bot, client, say, event, text)


def _approve_remediation(bot, body, client):
    """Run an approved remediation command and report the result."""
    data = json.loads(body["actions"][0]["value"])
    cmd = data["cmd"]
    alert = data.get("alert", "unknown")
    user = body["user"]["username"]
    channel = body["channel"]["id"]
    ts = body["message"]["ts"]

    log.info("Remediation approved by %s: %s", user, cmd)
    client.chat_update(
        channel=channel,
        ts=ts,
        text=f":hourglass: *Remediation approved by @{user}* — executing `{cmd}`...",
    )

    output, exit_code = execute_command(cmd)
    code_indicator = "" if exit_code == 0 else f" (exit {exit_code})"
    icon = ":white_check_mark:" if exit_code == 0 else ":x:"
    client.chat_update(
        channel=channel,
        ts=ts,
        text=(
            f"{icon} *Remediation executed* (approved by @{user})\n"
            f"*Command:* `{cmd}`{code_indicator}\n"
            f"```\n{output[:1500]}\n```"
        ),
    )
    audit.log_remediation(bot, user, alert, cmd, exit_code)


def _reject_remediation(body, client):
    """Mark a suggested remediation as declined."""
    user = body["user"]["username"]
    alert = body["actions"][0]["value"]
    client.chat_update(
        channel=body["channel"]["id"],
        ts=body["message"]["ts"],
        text=f":no_entry_sign: *Remediation declined* by @{user} for `{alert}`",
    )
    log.info("Remediation rejected by %s for %s", user, alert)


def _register_actions(bot):
    """Register the Approve / Reject remediation button handlers."""

    @bot.app.action("approve_remediation")
    def handle_approve(ack, body, client):
        ack()
        try:
            _approve_remediation(bot, body, client)
        except ACTION_ERRORS:
            log.exception("Remediation execution error")

    @bot.app.action("reject_remediation")
    def handle_reject(ack, body, client):
        ack()
        try:
            _reject_remediation(body, client)
        except ACTION_ERRORS:
            log.exception("Remediation rejection error")


def _start_thread(target, bot):
    """Start a background daemon thread running target(bot)."""
    threading.Thread(target=target, args=(bot,), daemon=True).start()


def _start_background_threads(bot):
    """Start alert polling, idle check-ins, health digest, and alert worker."""
    cfg = bot.config
    _start_thread(alerts.alert_poll_loop, bot)
    log.info("Alert poll thread started (interval=%ds)", cfg.alert_poll_interval)

    _start_thread(idle.idle_health_loop, bot)
    log.info(
        "Idle thread started (interval=%ds, mention=<@%s>)",
        cfg.idle_interval,
        cfg.idle_mention_user,
    )

    _start_thread(digest.health_digest_loop, bot)
    log.info(
        "Health digest thread started (hour=%d, enabled=%s)",
        cfg.digest_hour,
        cfg.digest_enabled,
    )

    # gh failures are logged per label by execute_command; never raises.
    github.ensure_labels(cfg.github_repo, cfg.alert_channels)
    log.info("GitHub alert labels ensured")

    _start_thread(alerts.alert_worker_loop, bot)
    log.info(
        "Alert investigation worker started (cooldown=%dh, max_rounds=%d)",
        cfg.alert_cooldown_hours,
        cfg.alert_max_rounds,
    )


def main():
    """Start the bot: connect to Slack and the LLM, then run Socket Mode."""
    cfg = config.load()

    app = App(token=cfg.slack_bot_token)
    llm_client = OpenAI(api_key=cfg.opencode_api_key, base_url=cfg.api_base)

    bot = Bot(app=app, llm=llm_client, config=cfg)
    bot.personality = personality_mod.load(cfg.personality_file) or ""
    bot.db = knowledge.init_db(cfg.knowledge_db_path)

    auth = app.client.auth_test()
    bot.bot_user_id = str(auth["user_id"])
    log.info("FIO Bot started as %s (%s)", auth["user"], bot.bot_user_id)
    log.info("Listening in channel %s, model %s", cfg.channel, cfg.model)
    if bot.personality:
        log.info("Active personality: %s", bot.personality[:100])

    _discover_alert_channels(bot)

    # fetch_alert_summary reports Alertmanager failures in its return value.
    initial = alerts.fetch_alert_summary(cfg)
    with bot.alert_summary_lock:
        bot.alert_summary = initial
    log.info("Initial alert summary: %s", initial[:200])

    _register_handlers(bot)
    _register_actions(bot)
    commands.register(bot)
    _start_background_threads(bot)

    if cfg.audit_channel:
        try:
            app.client.conversations_join(channel=cfg.audit_channel)
            log.info("Joined audit channel %s", cfg.audit_channel)
        except SLACK_ERRORS as e:
            log.warning("Could not join audit channel %s: %s", cfg.audit_channel, e)

    handler = SocketModeHandler(app, cfg.slack_app_token)
    handler.start()


if __name__ == "__main__":
    main()
