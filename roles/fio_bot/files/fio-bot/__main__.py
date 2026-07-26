#!/usr/bin/env python3
"""FIO Bot — FeedItOut ChatOps Slack bot."""

import logging
import queue
import sys
import threading
from collections import defaultdict
from dataclasses import dataclass, field

from openai import OpenAI
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

import json

import config
import audit
import knowledge
import personality as personality_mod
import alerts
import commands
import digest
import idle
import github
from executor import execute_command
from llm import chat_with_llm, fetch_thread_context

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("fio-bot")


@dataclass
class Bot:
    app: App
    llm: OpenAI
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
    try:
        result = bot.app.client.users_conversations(types="public_channel", limit=200)
        channels = result.get("channels", [])
        alert_channels = {}
        for ch in channels:
            name = ch.get("name", "")
            if name.startswith("alert-") and name != "alert-audit":
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
    except Exception as e:
        log.error("Failed to discover alert channels: %s", e)


def _get_thread_key(event):
    return event.get("thread_ts") or event.get("ts")


def _register_handlers(bot):

    @bot.app.event("message")
    def handle_message(event, say, client):
        channel = event.get("channel", "")

        if channel in bot.config.alert_channel_ids:
            subtype = event.get("subtype", "")
            if subtype and subtype != "bot_message":
                return
            if event.get("thread_ts"):
                return
            alerts.maybe_enqueue_alert(bot, event, channel, client)
            return

        if event.get("subtype"):
            return
        if bot.bot_user_id and event.get("user") == bot.bot_user_id:
            return

        text = event.get("text", "").strip()
        if not text:
            return

        if channel.startswith("D"):
            if bot.bot_user_id:
                text = text.replace(f"<@{bot.bot_user_id}>", "").strip()
            try:
                if text.lower() == "reset":
                    with bot.personality_lock:
                        bot.personality = ""
                    personality_mod.save(bot.config.personality_file, None)
                    say(
                        text="Personality reset to default FIO Bot.", channel=channel
                    )
                    log.info("Personality reset by %s", event.get("user"))
                else:
                    with bot.personality_lock:
                        bot.personality = (
                            personality_mod.save(bot.config.personality_file, text)
                            or ""
                        )
                    say(text=f"Personality set to:\n> {text}", channel=channel)
                    log.info("Personality set by %s: %s", event.get("user"), text[:100])
            except Exception as e:
                log.exception("Error handling DM from %s: %s", event.get("user"), e)
                try:
                    say(text=f"Error setting personality: {e}", channel=channel)
                except Exception:
                    pass
            return

        if channel != bot.config.channel:
            return

        if bot.bot_user_id:
            text = text.replace(f"<@{bot.bot_user_id}>", "").strip()

        thread_key = _get_thread_key(event)
        thread_ts = event.get("thread_ts") or event.get("ts")

        try:
            client.reactions_add(
                channel=bot.config.channel, name="eyes", timestamp=event["ts"]
            )
        except Exception:
            pass

        log.info("MSG from %s: %s", event.get("user"), text[:100])
        audit.log_chat(bot, event.get("user", "unknown"), text)

        try:
            response = chat_with_llm(bot, thread_key, thread_ts, text)

            if len(response) > 3900:
                chunks = [response[i : i + 3900] for i in range(0, len(response), 3900)]
                for chunk in chunks:
                    say(text=chunk, thread_ts=thread_ts)
            else:
                say(text=response, thread_ts=thread_ts)

            try:
                client.reactions_add(
                    channel=bot.config.channel,
                    name="white_check_mark",
                    timestamp=event["ts"],
                )
            except Exception:
                pass
        except Exception as e:
            log.exception("Error handling message")
            say(text=f"Error: {e}", thread_ts=thread_ts)

        try:
            client.reactions_remove(
                channel=bot.config.channel, name="eyes", timestamp=event["ts"]
            )
        except Exception:
            pass

    @bot.app.event("app_mention")
    def handle_mention(event, say, client):
        channel = event.get("channel")
        if channel == bot.config.channel:
            return

        if event.get("subtype"):
            return

        text = event.get("text", "").strip()
        if bot.bot_user_id:
            text = text.replace(f"<@{bot.bot_user_id}>", "").strip()
        if not text:
            return

        thread_ts = event.get("thread_ts") or event.get("ts")
        thread_key = _get_thread_key(event)

        try:
            client.reactions_add(channel=channel, name="eyes", timestamp=event["ts"])
        except Exception:
            pass

        log.info("MENTION in %s from %s: %s", channel, event.get("user"), text[:100])

        if event.get("thread_ts"):
            thread_context = fetch_thread_context(client, channel, event["thread_ts"])
            if thread_context:
                text = (
                    f"The user is asking from within a Slack thread. "
                    f"Here is the full thread conversation for context:\n"
                    f"---\n{thread_context}\n---\n\n"
                    f"The user's request: {text}"
                )

        try:
            response = chat_with_llm(bot, thread_key, thread_ts, text, channel=channel)
            if len(response) > 3900:
                chunks = [response[i : i + 3900] for i in range(0, len(response), 3900)]
                for chunk in chunks:
                    say(text=chunk, thread_ts=thread_ts, channel=channel)
            else:
                say(text=response, thread_ts=thread_ts, channel=channel)
            try:
                client.reactions_add(
                    channel=channel, name="white_check_mark", timestamp=event["ts"]
                )
            except Exception:
                pass
        except Exception as e:
            log.exception("Error handling mention")
            say(text=f"Error: {e}", thread_ts=thread_ts, channel=channel)

        try:
            client.reactions_remove(channel=channel, name="eyes", timestamp=event["ts"])
        except Exception:
            pass


def _register_actions(bot):

    @bot.app.action("approve_remediation")
    def handle_approve(ack, body, client):
        ack()
        try:
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
        except Exception as e:
            log.exception("Remediation execution error: %s", e)

    @bot.app.action("reject_remediation")
    def handle_reject(ack, body, client):
        ack()
        try:
            user = body["user"]["username"]
            alert = body["actions"][0]["value"]
            channel = body["channel"]["id"]
            ts = body["message"]["ts"]

            client.chat_update(
                channel=channel,
                ts=ts,
                text=f":no_entry_sign: *Remediation declined* by @{user} for `{alert}`",
            )

            log.info("Remediation rejected by %s for %s", user, alert)
        except Exception as e:
            log.exception("Remediation rejection error: %s", e)


def main():
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

    try:
        initial = alerts.fetch_alert_summary(cfg)
        with bot.alert_summary_lock:
            bot.alert_summary = initial
        log.info("Initial alert summary: %s", initial[:200])
    except Exception as e:
        log.error("Initial alert fetch failed: %s", e)

    _register_handlers(bot)
    _register_actions(bot)
    commands.register(bot)

    threading.Thread(target=alerts.alert_poll_loop, args=(bot,), daemon=True).start()
    log.info("Alert poll thread started (interval=%ds)", cfg.alert_poll_interval)

    threading.Thread(target=idle.idle_health_loop, args=(bot,), daemon=True).start()
    log.info(
        "Idle thread started (interval=%ds, mention=<@%s>)",
        cfg.idle_interval,
        cfg.idle_mention_user,
    )

    threading.Thread(target=digest.health_digest_loop, args=(bot,), daemon=True).start()
    log.info(
        "Health digest thread started (hour=%d, enabled=%s)",
        cfg.digest_hour,
        cfg.digest_enabled,
    )

    try:
        github.ensure_labels(cfg.github_repo, cfg.alert_channels)
        log.info("GitHub alert labels ensured")
    except Exception as e:
        log.warning("Failed to ensure GitHub labels: %s", e)

    threading.Thread(target=alerts.alert_worker_loop, args=(bot,), daemon=True).start()
    log.info(
        "Alert investigation worker started (cooldown=%dh, max_rounds=%d)",
        cfg.alert_cooldown_hours,
        cfg.alert_max_rounds,
    )

    if cfg.audit_channel:
        try:
            app.client.conversations_join(channel=cfg.audit_channel)
            log.info("Joined audit channel %s", cfg.audit_channel)
        except Exception as e:
            log.warning("Could not join audit channel %s: %s", cfg.audit_channel, e)

    handler = SocketModeHandler(app, cfg.slack_app_token)
    handler.start()


if __name__ == "__main__":
    main()
