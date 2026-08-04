"""Loads secrets.yaml (gitignored -- copy secrets.yaml.example and fill
in your own values). Returns {} if the file doesn't exist, so a missing
secrets file disables the features that need it (currently just threat
intel) instead of crashing the app.
"""

import os

import yaml


def load(directory: str) -> dict:
    path = os.path.join(directory, "secrets.yaml")
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        return yaml.safe_load(f) or {}


def save(directory: str, secrets: dict) -> None:
    """Overwrites secrets.yaml with `secrets` (e.g. from the desktop app's
    Settings tab). Only ever called with data the user typed into the
    app itself -- never with anything from an external/untrusted source."""
    path = os.path.join(directory, "secrets.yaml")
    with open(path, "w") as f:
        yaml.safe_dump(secrets, f, sort_keys=False)
