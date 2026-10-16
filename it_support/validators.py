"""Input checks shared by all tools. Bad input is rejected before touching data."""

from __future__ import annotations

import re

EMPLOYEE_ID_PATTERN = re.compile(r"^EMP\d{3}$")
DEVICE_ID_PATTERN = re.compile(r"^DEV-\d{4}$")
SITE_PATTERN = re.compile(r"^[A-Z]+(-[A-Z]+)*$")


def _clean(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip().upper()
    return value or None


def normalize_employee_id(value: object) -> str | None:
    """'emp002 ' -> 'EMP002'. Returns None if the format is wrong."""
    value = _clean(value)
    return value if value and EMPLOYEE_ID_PATTERN.fullmatch(value) else None


def normalize_device_id(value: object) -> str | None:
    """'dev-1001' -> 'DEV-1001'. Returns None if the format is wrong."""
    value = _clean(value)
    return value if value and DEVICE_ID_PATTERN.fullmatch(value) else None


def normalize_site(value: object) -> str | None:
    """'cairo hq' -> 'CAIRO-HQ'. Returns None if the format is wrong."""
    value = _clean(value)
    if value:
        value = re.sub(r"[\s_]+", "-", value)
    return value if value and len(value) <= 40 and SITE_PATTERN.fullmatch(value) else None
