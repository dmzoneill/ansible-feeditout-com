"""Behaviour tests for /fio error handling after narrowing to COMMAND_ERRORS.

Expected command errors are reported back to Slack; anything else propagates.
"""

import sqlite3
from types import SimpleNamespace

import commands
import pytest
from openai import OpenAIError
from slack_sdk.errors import SlackApiError

EXPECTED = [
    SlackApiError("slack", {"ok": False}),
    OpenAIError("llm"),
    sqlite3.Error("db"),
    OSError("io"),
    ValueError("bad"),
    KeyError("key"),
]


def _fake_app():
    """Slack app stand-in that records the registered slash command."""
    handlers = {}

    def command(name):
        def wrap(func):
            handlers[name] = func
            return func

        return wrap

    return SimpleNamespace(command=command, handlers=handlers)


@pytest.fixture(name="fio")
def fixture_fio():
    """Run /fio with the given text and return the texts sent back."""
    app = _fake_app()
    config = SimpleNamespace(audit_channel="")
    commands.register(SimpleNamespace(app=app, config=config))

    def run(text):
        sent = []
        app.handlers["/fio"](
            ack=lambda: None,
            command={"text": text, "user_name": "dave", "trigger_id": "t1"},
            respond=lambda **kw: sent.append(kw["text"]),
        )
        return sent

    return run


def _raiser(error):
    def handler(*_args):
        raise error

    return handler


@pytest.mark.parametrize("error", EXPECTED, ids=lambda e: type(e).__name__)
def test_expected_handler_error_is_reported(fio, monkeypatch, error):
    """A listed error from a subcommand becomes an error reply."""
    monkeypatch.setitem(commands.HANDLERS, "status", _raiser(error))
    assert fio("status") == [f"Error running `status`: {error}"]


def test_unexpected_handler_error_propagates(fio, monkeypatch):
    """An error outside COMMAND_ERRORS is no longer swallowed."""
    monkeypatch.setitem(commands.HANDLERS, "status", _raiser(RuntimeError("boom")))
    with pytest.raises(RuntimeError, match="boom"):
        fio("status")


@pytest.mark.parametrize("error", EXPECTED, ids=lambda e: type(e).__name__)
def test_expected_llm_error_in_ask_is_reported(fio, monkeypatch, error):
    """A listed LLM error in /fio ask is replied to in the thread."""
    monkeypatch.setattr(commands, "chat_with_llm", _raiser(error))
    assert fio("ask what is the load") == [":brain: Thinking...", f"Error: {error}"]


def test_unexpected_llm_error_in_ask_propagates(fio, monkeypatch):
    """An unexpected LLM error escapes both handlers."""
    monkeypatch.setattr(commands, "chat_with_llm", _raiser(RuntimeError("boom")))
    with pytest.raises(RuntimeError, match="boom"):
        fio("ask what is the load")
