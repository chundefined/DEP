"""Unit tests for the schema validation logic."""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

import dep.schemas
from dep.cli.validate import validate_file


@pytest.fixture
def validator() -> Draft202012Validator:
    schema_path = resources.files(dep.schemas) / "detection.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures"


def test_valid_minimal(validator: Draft202012Validator, fixtures_dir: Path) -> None:
    errors = validate_file(fixtures_dir / "valid" / "minimal.yml", validator)
    assert errors == 0


def test_valid_full(validator: Draft202012Validator, fixtures_dir: Path) -> None:
    errors = validate_file(fixtures_dir / "valid" / "full.yml", validator)
    assert errors == 0


@pytest.mark.parametrize(
    "name",
    [
        "missing-id",
        "bad-id-format",
        "bad-severity",
        "description-too-short",
    ],
)
def test_invalid_fixtures(
    validator: Draft202012Validator, fixtures_dir: Path, name: str
) -> None:
    errors = validate_file(fixtures_dir / "invalid" / f"{name}.yml", validator)
    assert errors > 0
