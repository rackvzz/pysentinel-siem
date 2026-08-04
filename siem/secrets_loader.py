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
