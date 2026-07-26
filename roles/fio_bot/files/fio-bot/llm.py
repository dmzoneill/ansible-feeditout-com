"""LLM interaction, action parsing, and chat loop."""

import json
import logging
import re
from datetime import datetime, timezone

from executor import execute_command, upload_file
from config import system_prompt, monitoring_reference

log = logging.getLogger("fio-bot")


def extract_commands(text):
    commands = []
    for match in re.finditer(r"```command\s*\n(.*?)\n\s*```", text, re.DOTALL):
        try:
            data = json.loads(match.group(1).strip())
            if "command" in data:
                commands.append(data["command"])
        except json.JSONDecodeError:
            pass
    for match in re.finditer(r'(?<![`\w])\{"command"\s*:\s*"([^"]+)"\}', text):
        cmd = match.group(1)
        if cmd not in commands:
            commands.append(cmd)
    return commands


def extract_uploads(text):
    uploads = []
    for match in re.finditer(r"```upload\s*\n\s*(\{[^}]+\})\s*\n\s*```", text):
        try:
            data = json.loads(match.group(1))
            if "file" in data or "content" in data:
                uploads.append(data)
        except json.JSONDecodeError:
            pass
    for match in re.finditer(r'(?<![`\w])\{"file"\s*:\s*"([^"]+)"', text):
        uploads.append({"file": match.group(1)})
    return uploads


def extract_slack_reads(text):
    reads = []
    for match in re.finditer(r"```slack\s*\n(.*?)\n\s*```", text, re.DOTALL):
        try:
            data = json.loads(match.group(1).strip())
            if "channel" in data:
                reads.append(data)
        except json.JSONDecodeError:
            pass
    return reads


def strip_actions(text):
    text = re.sub(r"```command\s*\n\s*\{[^}]+\}\s*\n\s*```", "", text)
    text = re.sub(r"```upload\s*\n\s*\{[^}]+\}\s*\n\s*```", "", text)
    text = re.sub(r"```slack\s*\n\s*\{[^}]+\}\s*\n\s*```", "", text)
    text = re.sub(r'(?<![`\w])\{"command"\s*:\s*"[^"]+"\}', "", text)
    text = re.sub(r'(?<![`\w])\{"file"\s*:\s*"[^"]+"\}', "", text)
    return text.strip()


def extract_message_text(msg):
    text = msg.get("text", "")
    if not text:
        for att in msg.get("attachments", []):
            fallback = att.get("fallback") or att.get("text") or att.get("pretext", "")
            if fallback:
                text = fallback
                break
    if not text:
        for block in msg.get("blocks", []):
            if block.get("type") == "section" and block.get("text", {}).get("text"):
                text = block["text"]["text"]
                break
    return text


def read_slack_channel(bot, channel_name, count=5):
    channel_id = bot.config.alert_channels.get(channel_name)
    if not channel_id:
        return f"Unknown channel '{channel_name}'. Available: {', '.join(bot.config.alert_channels.keys())}"
    try:
        result = bot.app.client.conversations_history(
            channel=channel_id, limit=min(count, 20)
        )
        messages = result.get("messages", [])
        if not messages:
            return f"No recent messages in #{channel_name}."
        lines = []
        for msg in reversed(messages):
            ts = float(msg.get("ts", 0))
            dt = datetime.fromtimestamp(ts, tz=timezone.utc).strftime(
                "%Y-%m-%d %H:%M UTC"
            )
            text = extract_message_text(msg)
            if not text:
                continue
            user = msg.get("username") or msg.get("user") or "bot"
            lines.append(f"[{dt}] {user}: {text}")
        return (
            "\n".join(lines) if lines else f"No readable messages in #{channel_name}."
        )
    except Exception as e:
        return f"Error reading #{channel_name}: {e}"


def fetch_thread_context(client, channel, thread_ts):
    try:
        result = client.conversations_replies(channel=channel, ts=thread_ts, limit=50)
        messages = result.get("messages", [])
        if len(messages) <= 1:
            return None
        parts = []
        for msg in messages:
            user = msg.get("user") or msg.get("username") or "app"
            text = extract_message_text(msg)
            if not text:
                continue
            if user == "app" or msg.get("bot_id"):
                parts.append(f"[bot]: {text}")
            else:
                parts.append(f"<@{user}>: {text}")
        return "\n".join(parts) if parts else None
    except Exception as e:
        log.error("Failed to fetch thread: %s", e)
        return None


def _get_system_prompt(bot):
    prompt = system_prompt(bot.config) + monitoring_reference(bot.config)
    with bot.alert_summary_lock:
        alert_ctx = bot.alert_summary
    if alert_ctx:
        prompt += (
            "\n--- CURRENT ALERT STATUS ---\n"
            + alert_ctx
            + "\n--- END ALERT STATUS ---"
        )
    with bot.personality_lock:
        personality = bot.personality
    if personality:
        prompt = personality + "\n\n" + prompt
    return prompt


def _trim_history(history, max_history):
    if len(history) > max_history * 2:
        del history[: len(history) - max_history * 2]


def chat_with_llm(bot, thread_key, thread_ts, user_message, channel=None):
    if channel is None:
        channel = bot.config.channel
    cfg = bot.config

    with bot.conversations_lock:
        bot.conversations[thread_key].append({"role": "user", "content": user_message})
        _trim_history(bot.conversations[thread_key], cfg.max_history)
        messages = [{"role": "system", "content": _get_system_prompt(bot)}] + list(
            bot.conversations[thread_key]
        )

    full_response_parts = []
    progress_messages = [
        ":hourglass_flowing_sand: I'm thinking...",
        ":gear: Still working on it...",
        ":hammer_and_wrench: Getting there...",
        ":mag: Almost done...",
    ]
    progress_interval = 3
    round_num = 0

    while True:
        if round_num > 0 and round_num % progress_interval == 0:
            msg_idx = min(
                round_num // progress_interval - 1, len(progress_messages) - 1
            )
            try:
                bot.app.client.chat_postMessage(
                    channel=channel,
                    thread_ts=thread_ts,
                    text=progress_messages[msg_idx],
                )
            except Exception:
                pass

        try:
            response = bot.llm.chat.completions.create(
                model=cfg.model,
                messages=messages,
                max_tokens=4096,
            )
        except Exception as e:
            log.error("LLM error: %s", e)
            return f"LLM error: {e}"

        reply = response.choices[0].message.content or ""
        commands = extract_commands(reply)
        uploads = extract_uploads(reply)
        slack_reads = extract_slack_reads(reply)
        display_text = strip_actions(reply)

        has_actions = bool(commands or slack_reads)

        if display_text and not has_actions:
            full_response_parts.append(display_text)

        if has_actions:
            uploads = []

        for upl in uploads:
            if "file" in upl:
                result = upload_file(
                    bot.app.client,
                    channel,
                    thread_ts,
                    file_path=upl["file"],
                    title=upl.get("title"),
                )
            elif "content" in upl:
                result = upload_file(
                    bot.app.client,
                    channel,
                    thread_ts,
                    content=upl["content"],
                    filename=upl.get("filename"),
                    title=upl.get("title"),
                )
            else:
                result = "invalid upload request"

            if result == "uploaded":
                full_response_parts.append(
                    f"Uploaded: {upl.get('title') or upl.get('filename') or upl.get('file')}"
                )
            else:
                full_response_parts.append(f"Upload failed: {result}")

        if not has_actions:
            break

        messages.append({"role": "assistant", "content": reply})

        for sr in slack_reads:
            ch_name = sr["channel"]
            count = sr.get("count", 5)
            log.info("SLACK READ: #%s (count=%d)", ch_name, count)
            result = read_slack_channel(bot, ch_name, count)
            messages.append(
                {
                    "role": "user",
                    "content": f"[SYSTEM] Slack channel #{ch_name} recent messages:\n{result}\nNow answer the user's question using this context.",
                }
            )

        for cmd in commands:
            output, exit_code = execute_command(
                cmd, cfg.command_timeout, cfg.max_output
            )
            code_indicator = "" if exit_code == 0 else f" (exit {exit_code})"
            cmd_result = f"```\n$ {cmd}{code_indicator}\n{output}\n```"
            full_response_parts.append(cmd_result)

            messages.append(
                {
                    "role": "user",
                    "content": f"[SYSTEM] Command `{cmd}` returned{code_indicator}:\n```\n{output}\n```\nNow give the user a clear answer based on this output. Always include the actual result, not just the command.",
                }
            )

        round_num += 1

    final_response = "\n\n".join(full_response_parts)

    with bot.conversations_lock:
        bot.conversations[thread_key].append(
            {"role": "assistant", "content": final_response}
        )
        _trim_history(bot.conversations[thread_key], cfg.max_history)

    return final_response
