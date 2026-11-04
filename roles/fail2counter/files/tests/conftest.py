"""Test fixtures that stub heavy third-party modules for the worker/ai units.

The ``ai`` and ``fail2counter_worker`` modules import ``anthropic``,
``psycopg2`` and ``redis`` at module load time.  These are not needed to
exercise the pure logic under test, so lightweight stand-ins are installed
in :data:`sys.modules` before the modules are imported.
"""

import pathlib
import sys
import types
from typing import Any

_FILES_DIR = pathlib.Path(__file__).resolve().parent.parent


def _make_module(name: str) -> Any:
    """Create and register an empty stub module under ``name``."""
    module = types.ModuleType(name)
    sys.modules[name] = module
    return module


def _install_stubs() -> None:
    """Install stub anthropic/psycopg2/redis modules if not already present."""
    if "anthropic" not in sys.modules:
        anthropic = _make_module("anthropic")
        anthropic.AnthropicError = type("AnthropicError", (Exception,), {})
        anthropic.AnthropicVertex = type("AnthropicVertex", (), {})

    if "psycopg2" not in sys.modules:
        psycopg2 = _make_module("psycopg2")
        psycopg2.Error = type("Error", (Exception,), {})
        psycopg2.connect = lambda *a, **k: None
        extras = _make_module("psycopg2.extras")
        extras.RealDictCursor = type("RealDictCursor", (), {})
        psycopg2.extras = extras

    if "redis" not in sys.modules:
        redis = _make_module("redis")
        redis.Redis = type("Redis", (), {})
        exceptions = _make_module("redis.exceptions")
        exceptions.RedisError = type("RedisError", (Exception,), {})
        redis.exceptions = exceptions


_install_stubs()

if str(_FILES_DIR) not in sys.path:
    sys.path.insert(0, str(_FILES_DIR))
