"""LLM interaction, action parsing, and chat loop."""

import importlib
import json
import logging
import re
from datetime import datetime, timezone

from config import monitoring_reference, system_prompt
from executor import execute_command, upload_file

log = logging.getLogger("fio-bot")

# Both SDKs are runtime dependencies of the bot; loaded by name so this
# module's import block is ordered the same way for isort, ruff and pylint.
SlackApiError = importlib.import_module("slack_sdk.errors").SlackApiError
OpenAIError = importlib.import_module("openai").OpenAIError

# Slack API errors plus network-level failures (connection resets, timeouts).
SLACK_ERRORS = (SlackApiError, OSError)

PROGRESS_MESSAGES = (
    ":hourglass_flowing_sand: I'm thinking...",
    ":gear: Still working on it...",
    ":hammer_and_wrench: Getting there...",
    ":mag: Almost done...",
)
PROGRESS_INTERVAL = 3

_SLACK_READ_HEAD = "[SYSTEM] Slack channel #{channel} recent messages:\n{result}\n"
_SLACK_READ_ASK = "Now answer the user's question using this context."
SLACK_READ_PROMPT = _SLACK_READ_HEAD + _SLACK_READ_ASK

_COMMAND_HEAD = "[SYSTEM] Command `{cmd}` returned{code}:\n```\n{output}\n```\n"
_COMMAND_ASK = "Now give the user a clear answer based on this output."
_COMMAND_NOTE = " Always include the actual result, not just the command."
COMMAND_RESULT_PROMPT = _COMMAND_HEAD + _COMMAND_ASK + _COMMAND_NOTE

ALERT_HEADER = "\n--- CURRENT ALERT STATUS ---\n"
ALERT_FOOTER = "\n--- END ALERT STATUS ---"


def _json_blocks(text, fence):
    """Yield decoded JSON objects from ```<fence> blocks, skipping bad JSON."""
    for match in re.finditer(rf"```{fence}\s*\n(.*?)\n\s*```", text, re.DOTALL):
        try:
            data = json.loads(match.group(1).strip())
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict):
            yield data


def extract_commands(text):
    """Shell commands requested by the LLM, in order, without duplicates."""
    blocks = _json_blocks(text, "command")
    commands = [data["command"] for data in blocks if "command" in data]
    for match in re.finditer(r'(?<![`\w])\{"command"\s*:\s*"([^"]+)"\}', text):
        cmd = match.group(1)
        if cmd not in commands:
            commands.append(cmd)
    return commands


def extract_uploads(text):
    """File or content uploads requested by the LLM."""
    uploads = []
    for match in re.finditer(r"```upload\s*\n\s*(\{[^}]+\})\s*\n\s*```", text):
        try:
            data = json.loads(match.group(1))
        except json.JSONDecodeError:
            continue
        if "file" in data or "content" in data:
            uploads.append(data)
    for match in re.finditer(r'(?<![`\w])\{"file"\s*:\s*"([^"]+)"', text):
        uploads.append({"file": match.group(1)})
    return uploads


def extract_slack_reads(text):
    """Slack channel reads requested by the LLM."""
    return [data for data in _json_blocks(text, "slack") if "channel" in data]


def strip_actions(text):
    """Remove action blocks so only the human-readable reply remains."""
    text = re.sub(r"```command\s*\n\s*\{[^}]+\}\s*\n\s*```", "", text)
    text = re.sub(r"```upload\s*\n\s*\{[^}]+\}\s*\n\s*```", "", text)
    text = re.sub(r"```slack\s*\n\s*\{[^}]+\}\s*\n\s*```", "", text)
    text = re.sub(r'(?<![`\w])\{"command"\s*:\s*"[^"]+"\}', "", text)
    text = re.sub(r'(?<![`\w])\{"file"\s*:\s*"[^"]+"\}', "", text)
    return text.strip()


def extract_message_text(msg):
    """Best readable text of a Slack message (text, attachment, or block)."""
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


def _format_history_line(msg):
    """One '[time] user: text' line for a channel message, or None."""
    text = extract_message_text(msg)
    if not text:
        return None
    ts = float(msg.get("ts", 0))
    dt = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    user = msg.get("username") or msg.get("user") or "bot"
    return f"[{dt}] {user}: {text}"


def read_slack_channel(bot, channel_name, count=5):
    """Recent messages of a configured alert channel as plain text."""
    channel_id = bot.config.alert_channels.get(channel_name)
    if not channel_id:
        available = ", ".join(bot.config.alert_channels.keys())
        return f"Unknown channel '{channel_name}'. Available: {available}"
    try:
        result = bot.app.client.conversations_history(
            channel=channel_id,
            limit=min(count, 20),
        )
        messages = result.get("messages", [])
        if not messages:
            return f"No recent messages in #{channel_name}."
        lines = [line for line in map(_format_history_line, reversed(messages)) if line]
    except (*SLACK_ERRORS, ValueError) as e:
        return f"Error reading #{channel_name}: {e}"
    return "\n".join(lines) if lines else f"No readable messages in #{channel_name}."


def fetch_thread_context(client, channel, thread_ts):
    """Earlier messages of a Slack thread, or None for a new/unreadable thread."""
    try:
        result = client.conversations_replies(channel=channel, ts=thread_ts, limit=50)
    except SLACK_ERRORS as e:
        log.error("Failed to fetch thread: %s", e)
        return None
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


def _get_system_prompt(bot):
    """System prompt with live alert status and personality prepended."""
    prompt = system_prompt(bot.config) + monitoring_reference(bot.config)
    with bot.alerts.summary_lock:
        alert_ctx = bot.alerts.summary
    if alert_ctx:
        prompt += ALERT_HEADER + alert_ctx + ALERT_FOOTER
    with bot.chat.personality_lock:
        personality = bot.chat.personality
    if personality:
        prompt = personality + "\n\n" + prompt
    return prompt


def _trim_history(history, max_history):
    """Keep only the last max_history user/assistant exchanges."""
    if len(history) > max_history * 2:
        del history[: len(history) - max_history * 2]


def _post_progress(bot, channel, thread_ts, round_num):
    """Every PROGRESS_INTERVAL rounds, tell the thread the bot is still working."""
    if round_num == 0 or round_num % PROGRESS_INTERVAL:
        return
    idx = min(round_num // PROGRESS_INTERVAL - 1, len(PROGRESS_MESSAGES) - 1)
    try:
        bot.app.client.chat_postMessage(
            channel=channel,
            thread_ts=thread_ts,
            text=PROGRESS_MESSAGES[idx],
        )
    except SLACK_ERRORS as e:
        # Progress pings are cosmetic; the real answer is posted later.
        log.warning("Could not post progress message: %s", e)


def _do_upload(bot, channel, thread_ts, upl):
    """Perform one upload request and return its line for the reply."""
    client = bot.app.client
    if "file" in upl:
        result = upload_file(
            client,
            channel,
            thread_ts,
            file_path=upl["file"],
            title=upl.get("title"),
        )
    elif "content" in upl:
        result = upload_file(
            client,
            channel,
            thread_ts,
            content=upl["content"],
            filename=upl.get("filename"),
            title=upl.get("title"),
        )
    else:
        result = "invalid upload request"
    if result == "uploaded":
        return f"Uploaded: {upl.get('title') or upl.get('filename') or upl.get('file')}"
    return f"Upload failed: {result}"


def _final_answer(bot, channel, thread_ts, reply):
    """Reply parts for an action-free answer, performing any uploads it asks."""
    parts = []
    display_text = strip_actions(reply)
    if display_text:
        parts.append(display_text)
    for upl in extract_uploads(reply):
        parts.append(_do_upload(bot, channel, thread_ts, upl))
    return parts


def _run_slack_reads(bot, slack_reads, messages):
    """Read requested channels and feed the results back to the LLM."""
    for sr in slack_reads:
        ch_name = sr["channel"]
        count = sr.get("count", 5)
        log.info("SLACK READ: #%s (count=%d)", ch_name, count)
        result = read_slack_channel(bot, ch_name, count)
        content = SLACK_READ_PROMPT.format(channel=ch_name, result=result)
        messages.append({"role": "user", "content": content})


def _run_commands(cfg, commands, messages, response_parts):
    """Execute requested commands; show output and feed it back to the LLM."""
    for cmd in commands:
        output, exit_code = execute_command(cmd, cfg.command_timeout, cfg.max_output)
        code = "" if exit_code == 0 else f" (exit {exit_code})"
        response_parts.append(f"```\n$ {cmd}{code}\n{output}\n```")
        content = COMMAND_RESULT_PROMPT.format(cmd=cmd, code=code, output=output)
        messages.append({"role": "user", "content": content})


def _ask_llm(bot, messages):
    """One completion round; returns the reply text (may be empty)."""
    response = bot.llm.chat.completions.create(
        model=bot.config.model,
        messages=messages,
        max_tokens=4096,
    )
    return response.choices[0].message.content or ""


def chat_with_llm(bot, thread_key, thread_ts, user_message, channel=None):
    """Answer a user message, running any commands/reads the LLM asks for."""
    if channel is None:
        channel = bot.config.channel
    cfg = bot.config

    with bot.chat.conversations_lock:
        history = bot.chat.conversations[thread_key]
        history.append({"role": "user", "content": user_message})
        _trim_history(history, cfg.max_history)
        messages = [{"role": "system", "content": _get_system_prompt(bot)}, *history]

    response_parts = []
    round_num = 0

    while True:
        _post_progress(bot, channel, thread_ts, round_num)

        try:
            reply = _ask_llm(bot, messages)
        except OpenAIError as e:
            log.error("LLM error: %s", e)
            return f"LLM error: {e}"

        commands = extract_commands(reply)
        slack_reads = extract_slack_reads(reply)

        if not (commands or slack_reads):
            response_parts.extend(_final_answer(bot, channel, thread_ts, reply))
            break

        messages.append({"role": "assistant", "content": reply})
        _run_slack_reads(bot, slack_reads, messages)
        _run_commands(cfg, commands, messages, response_parts)
        round_num += 1

    final_response = "\n\n".join(response_parts)

    with bot.chat.conversations_lock:
        history = bot.chat.conversations[thread_key]
        history.append({"role": "assistant", "content": final_response})
        _trim_history(history, cfg.max_history)

    return final_response
