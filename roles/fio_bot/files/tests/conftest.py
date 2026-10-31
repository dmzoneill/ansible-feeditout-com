"""Make the fio-bot modules importable from the tests.

fio-bot runs as a directory of flat modules (``python fio-bot``), so its
modules import each other by bare name and the entry point is
``__main__.py``. Put the directory on sys.path and expose ``__main__.py``
as ``fio_bot_main``.
"""

import importlib.util
import os
import sys
from pathlib import Path

BOT_DIR = Path(__file__).resolve().parent.parent / "fio-bot"
sys.path.insert(0, str(BOT_DIR))
for _name in ("SLACK_BOT_TOKEN", "SLACK_APP_TOKEN", "OPENCODE_ZEN_API_KEY"):
    os.environ.setdefault(_name, "test")

_spec = importlib.util.spec_from_file_location("fio_bot_main", BOT_DIR / "__main__.py")
if _spec is None or _spec.loader is None:
    raise ImportError(f"cannot load {BOT_DIR / '__main__.py'}")
_main = importlib.util.module_from_spec(_spec)
sys.modules["fio_bot_main"] = _main
_spec.loader.exec_module(_main)
