#!/usr/bin/env python3
"""Canonical machine_id validation for Data Relay Link.

Immutable client identity must be validated consistently across:
  - /bootstrap/redeem
  - /enroll
  - management mutation authentication
  - management read authentication
  - registry selectors that accept raw machine identity
"""
from __future__ import annotations

MACHINE_ID_MAX_LEN = 128


class MachineIdError(ValueError):
    """Invalid machine_id."""


def validate_machine_id(value, *, required: bool = True) -> str:
    """Return a validated machine_id string or raise MachineIdError.

    Rules:
      - required (when required=True)
      - length 1..MACHINE_ID_MAX_LEN
      - no CR / LF / slash / backslash
      - no C0/C1 control characters
    """
    if value is None:
        text = ""
    else:
        text = str(value).strip()
    if not text:
        if required:
            raise MachineIdError("machine_id is required")
        return ""
    if len(text) > MACHINE_ID_MAX_LEN:
        raise MachineIdError("machine_id too long")
    for ch in text:
        o = ord(ch)
        if ch in "\r\n/\\" or o < 0x20 or (0x7F <= o <= 0x9F):
            raise MachineIdError("invalid machine_id")
    return text


def is_valid_machine_id(value) -> bool:
    try:
        validate_machine_id(value, required=True)
        return True
    except MachineIdError:
        return False
