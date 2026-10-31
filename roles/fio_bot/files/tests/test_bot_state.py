"""Behaviour tests for the shared Bot state used across fio-bot modules.

They only go through module functions, never Bot attributes, so the same
tests pass before and after the state layout changes.
"""

import alerts
import config
import llm
import pytest
from alerts import _poll_once, _process_next_alert
from commands import _cmd_alerts, _cmd_personality
from digest import _alerts_section
from fio_bot_main import Bot, _handle_dm
from llm import _get_system_prompt

DEFAULT_PERSONALITY = "*Current Personality*\nDefault (no custom personality set)"


@pytest.fixture(name="bot")
def fixture_bot(tmp_path):
    """A Bot with real config and a personality file under tmp_path."""
    cfg = config.load()
    cfg.personality_file = str(tmp_path / "personality")
    return Bot(app=None, llm=None, config=cfg)


def _responses(func, bot):
    """Texts a /fio handler sends through respond()."""
    out = []
    func(bot, "", lambda **kw: out.append(kw["text"]))
    return out


def test_new_bot_has_no_alerts_or_personality(bot):
    """A fresh Bot reports no alert data and the default personality."""
    assert _responses(_cmd_alerts, bot) == ["*Alerts*\nNo alert data available yet."]
    assert _responses(_cmd_personality, bot) == [DEFAULT_PERSONALITY]
    assert _alerts_section(bot) == ":white_circle: *Alerts* — No data"
    base = config.system_prompt(bot.config) + config.monitoring_reference(bot.config)
    assert _get_system_prompt(bot) == base


def test_alert_summary_is_shared(bot, monkeypatch):
    """The polled summary reaches /fio alerts, the digest and the LLM prompt."""
    monkeypatch.setattr(alerts, "fetch_alert_summary", lambda cfg: "2 alert(s) firing")
    _poll_once(bot, cleanup_due=False)
    assert _responses(_cmd_alerts, bot) == ["*Alerts*\n2 alert(s) firing"]
    assert _alerts_section(bot).endswith("*Alerts*\n2 alert(s) firing")
    assert "2 alert(s) firing" in _get_system_prompt(bot)


def test_personality_set_and_reset(bot):
    """A DM sets the personality everywhere; 'reset' clears it."""
    said = []
    _handle_dm(bot, {"channel": "D1"}, lambda **kw: said.append(kw), "be terse")
    assert _responses(_cmd_personality, bot) == ["*Current Personality*\n> be terse"]
    assert _get_system_prompt(bot).startswith("be terse\n\n")
    _handle_dm(bot, {"channel": "D1"}, lambda **kw: said.append(kw), "reset")
    assert _responses(_cmd_personality, bot) == [DEFAULT_PERSONALITY]
    assert len(said) == 2


def test_cooldown_per_alert_and_instance(bot):
    """Cooldowns are tracked per (alertname, instance)."""
    assert not alerts.is_on_cooldown(bot, "Disk", "h1")
    alerts.mark_processed(bot, "Disk", "h1")
    assert alerts.is_on_cooldown(bot, "Disk", "h1")
    assert not alerts.is_on_cooldown(bot, "Disk", "h2")


def test_queued_alert_reaches_worker(bot, monkeypatch):
    """An enqueued alert is handed to process_alert with its routing info."""
    alert = {"alertname": "Disk", "instance": "h1", "status": "FIRING"}
    monkeypatch.setattr(
        alerts,
        "parse_alert_from_event",
        lambda event, cats: dict(alert),
    )
    seen = []
    monkeypatch.setattr(alerts, "process_alert", lambda b, data: seen.append(data))
    alerts.maybe_enqueue_alert(bot, {"ts": "1.0"}, "C1", "client")
    _process_next_alert(bot)
    assert seen[0]["alertname"] == "Disk"
    assert seen[0]["cooldown_only"] is False
    assert seen[0]["thread_ts"] == "1.0"


def test_conversation_history_kept_per_thread(bot, monkeypatch):
    """Each thread keeps its own history across chat_with_llm calls."""
    sent = []

    def fake_ask(_bot, messages):
        sent.append([m["content"] for m in messages[1:]])
        return f"answer {len(sent)}"

    monkeypatch.setattr(llm, "_ask_llm", fake_ask)
    monkeypatch.setattr(llm, "_final_answer", lambda b, c, t, reply: [reply])
    assert llm.chat_with_llm(bot, "t1", "t1", "hello", channel="C1") == "answer 1"
    assert llm.chat_with_llm(bot, "t1", "t1", "again", channel="C1") == "answer 2"
    llm.chat_with_llm(bot, "t2", "t2", "other", channel="C1")
    assert sent == [["hello"], ["hello", "answer 1", "again"], ["other"]]
