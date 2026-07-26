"""Shell command execution and Slack file uploads."""

import logging
import subprocess
from pathlib import Path

log = logging.getLogger("fio-bot")


def execute_command(cmd, timeout=30, max_output=3000):
    log.info("EXEC: %s", cmd)
    try:
        result = subprocess.run(
            ["script", "-qefc", cmd, "/dev/null"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = result.stdout
        if result.stderr:
            output += "\n" + result.stderr
        output = output.strip()
        if len(output) > max_output:
            output = (
                output[:max_output] + f"\n... (truncated, {len(output)} total chars)"
            )
        if not output:
            output = "(no output)"
        return output, result.returncode
    except subprocess.TimeoutExpired:
        return f"(command timed out after {timeout}s)", -1
    except Exception as e:
        return f"(error: {e})", -1


def upload_file(
    client, channel, thread_ts, file_path=None, content=None, filename=None, title=None
):
    log.info("UPLOAD: file=%s filename=%s title=%s", file_path, filename, title)
    try:
        if file_path:
            p = Path(file_path)
            if not p.exists():
                return f"File not found: {file_path}"
            if p.stat().st_size > 50 * 1024 * 1024:
                return f"File too large (>50MB): {file_path}"
            result = client.files_upload_v2(
                channel=channel,
                thread_ts=thread_ts,
                file=file_path,
                filename=filename or p.name,
                title=title or p.name,
            )
        elif content:
            result = client.files_upload_v2(
                channel=channel,
                thread_ts=thread_ts,
                content=content,
                filename=filename or "snippet.txt",
                title=title or filename or "snippet.txt",
            )
        else:
            return "No file path or content provided"

        if result.get("ok"):
            return "uploaded"
        return f"Upload failed: {result.get('error', 'unknown')}"
    except Exception as e:
        log.error("Upload error: %s", e)
        return f"Upload error: {e}"
