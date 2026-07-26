"""Personality persistence — load and save custom bot personality."""

import logging
from pathlib import Path

log = logging.getLogger("fio-bot")


def load(path):
    p = Path(path)
    if p.exists():
        text = p.read_text().strip()
        if text:
            log.info("Loaded personality: %s", text[:100])
            return text
    return None


def save(path, text):
    p = Path(path)
    cleaned = text.strip() if text and text.strip() else None
    if cleaned:
        p.write_text(cleaned + "\n")
    elif p.exists():
        p.unlink()
    return cleaned
