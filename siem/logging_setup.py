"""Shared logging configuration for both entrypoints (run_collector.py and
desktop_app.py).

Console-only logging (what run_collector.py used to do with a bare
`logging.basicConfig`) is invisible in two real scenarios this project
actually runs in: `pythonw.exe` (no console at all -- the desktop app's
whole reason for existing) and a console window the user closed after
launch. A rotating file next to the database means a crash is always
findable after the fact, in both entrypoints, without a console attached.
"""

import logging
import os
from logging.handlers import RotatingFileHandler

LOG_FILENAME = "pysentinel-siem.log"


def configure_logging(app_dir: str, level: int = logging.INFO) -> None:
    """Idempotent: safe to call more than once (e.g. a test importing both
    entrypoints) -- clears any handlers this already installed rather than
    stacking duplicate ones."""
    root = logging.getLogger()
    root.setLevel(level)
    for h in list(root.handlers):
        if getattr(h, "_pysentinel_handler", False):
            root.removeHandler(h)

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    console = logging.StreamHandler()
    console.setFormatter(fmt)
    console._pysentinel_handler = True
    root.addHandler(console)

    log_path = os.path.join(app_dir, LOG_FILENAME)
    try:
        file_handler = RotatingFileHandler(log_path, maxBytes=2_000_000, backupCount=3, encoding="utf-8")
        file_handler.setFormatter(fmt)
        file_handler._pysentinel_handler = True
        root.addHandler(file_handler)
    except OSError:
        # Read-only install directory or similar -- console logging (if any
        # console is attached) still works, just no persisted file.
        logging.getLogger("siem.logging_setup").warning(
            "Could not open %s for writing -- file logging disabled.", log_path
        )
