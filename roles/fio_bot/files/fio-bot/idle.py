"""Idle health check posting loop."""

import logging
import os
import time

log = logging.getLogger("fio-bot")


def _get_health_summary():
    """Return a brief system health string: load avg, disk usage, memory."""
    parts = []

    # Load average
    try:
        load1, load5, load15 = os.getloadavg()
        parts.append(f"Load: {load1:.2f} / {load5:.2f} / {load15:.2f}")
    except OSError:
        parts.append("Load: unavailable")

    # Disk usage (root filesystem)
    try:
        st = os.statvfs("/")
        total = st.f_blocks * st.f_frsize
        free = st.f_bavail * st.f_frsize
        used_pct = ((total - free) / total) * 100 if total else 0
        total_gb = total / (1024 ** 3)
        free_gb = free / (1024 ** 3)
        parts.append(
            f"Disk: {used_pct:.1f}% used ({free_gb:.1f}G free / {total_gb:.1f}G total)"
        )
    except OSError:
        parts.append("Disk: unavailable")

    # Memory usage from /proc/meminfo
    try:
        meminfo = {}
        with open("/proc/meminfo", "r") as f:
            for line in f:
                key, _, val = line.partition(":")
                # Values are in kB
                meminfo[key.strip()] = int(val.strip().split()[0])
        mem_total = meminfo.get("MemTotal", 0)
        mem_avail = meminfo.get("MemAvailable", 0)
        if mem_total:
            used_pct = ((mem_total - mem_avail) / mem_total) * 100
            total_gb = mem_total / (1024 ** 2)
            avail_gb = mem_avail / (1024 ** 2)
            parts.append(
                f"Mem: {used_pct:.1f}% used ({avail_gb:.1f}G avail / {total_gb:.1f}G total)"
            )
        else:
            parts.append("Mem: unavailable")
    except (OSError, ValueError, KeyError):
        parts.append("Mem: unavailable")

    return " | ".join(parts)


def idle_health_loop(bot):
    """Post a system health check to the channel when it has been idle."""
    while True:
        time.sleep(bot.config.idle_interval)
        try:
            oldest = str(time.time() - bot.config.idle_interval)
            result = bot.app.client.conversations_history(
                channel=bot.config.channel,
                oldest=oldest,
                limit=1,
            )
            messages = result.get("messages", [])
            has_activity = any(
                not m.get("subtype") and m.get("user") != bot.bot_user_id
                for m in messages
            )
            if not has_activity:
                health = _get_health_summary()
                bot.app.client.chat_postMessage(
                    channel=bot.config.channel,
                    text=f":heartbeat: System health: {health}",
                )
                log.info("Posted idle health check")
        except Exception as e:
            log.error("Idle health loop error: %s", e)
