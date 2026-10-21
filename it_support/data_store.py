"""Loads the mock data files. Every tool reads data through here."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

DATA_DIR = Path(__file__).resolve().parent / "data"
SYSTEMS_FILE = "mock_systems.json"


class DataUnavailableError(Exception):
    """Raised when a data source is missing, broken, or offline."""


@lru_cache(maxsize=None)
def load_json(file_name: str) -> dict[str, Any]:
    """Read a JSON file from the data folder (cached after the first read)."""
    path = DATA_DIR / file_name
    try:
        with path.open(encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise DataUnavailableError(f"Could not load data file '{file_name}'.") from exc


def get_section(section: str) -> dict[str, Any]:
    """Return one section of the systems data, e.g. 'accounts' or 'vpn'."""
    data = load_json(SYSTEMS_FILE)
    if section not in data:
        raise DataUnavailableError(f"Data section '{section}' is missing.")
    return data[section]
