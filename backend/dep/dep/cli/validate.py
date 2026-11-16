#!/usr/bin/env python3
"""DEP - Validator for `detection.yml` files against the JSON Schema.

This module holds the pure validation logic. The command-line interface lives
in `dep.cli.main`.

Error code emitted:
    DEP-SCH-001   The YAML does not comply with the JSON Schema

Note on dates
-------------
YAML 1.1 types `2026-08-15` as `datetime.date`, not as a string. JSON Schema has
no native `date` type: it uses `{"type": "string", "format": "date"}`. Validating
the raw result of `yaml.safe_load()` therefore produces false errors of the form
`datetime.date(...) is not of type 'string'` on EVERY date field.

The fix is NOT to quote dates in the YAML (unreadable, and easy to forget).
The fix is to normalize to ISO-8601 before validating, which is what
`_normalize()` does. Any other validator in the project (CI, API, UI) must do
the same.
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator


def _normalize(node):
    """Convert date/datetime values to ISO-8601 strings, recursively."""
    if isinstance(node, dict):
        return {k: _normalize(v) for k, v in node.items()}
    if isinstance(node, list):
        return [_normalize(v) for v in node]
    if isinstance(node, dt.datetime):
        return node.isoformat()
    if isinstance(node, dt.date):
        return node.isoformat()
    return node


def validate_file(path: Path, validator: Draft202012Validator) -> int:
    """Validate a single detection.yml file and return the number of errors."""
    errors = 0
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    doc = _normalize(raw)

    # --- DEP-SCH-001 -------------------------------------------------------
    for err in sorted(validator.iter_errors(doc), key=lambda e: list(e.path)):
        location = "/".join(str(p) for p in err.path) or "<root>"
        print(f"  DEP-SCH-001  {location}: {err.message}")
        errors += 1

    return errors
