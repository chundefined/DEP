"""Unit tests for the repository validation engine."""

from __future__ import annotations

from pathlib import Path

import pytest

from dep.repo import DetectionRepository
from dep.validation.repo_validator import validate_repository


@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures" / "repos"


def test_valid_repository_has_no_errors(fixtures_dir: Path) -> None:
    repo = DetectionRepository(fixtures_dir / "valid")
    errors = validate_repository(repo)
    assert len(errors) == 0


def test_missing_referenced_file_reported(fixtures_dir: Path) -> None:
    repo = DetectionRepository(fixtures_dir / "missing-referenced-file")
    errors = validate_repository(repo)
    assert len(errors) == 1
    assert errors[0].code == "DEP-FIL-004"
    assert "implementations/0/logic/file" in errors[0].location


def test_duplicate_detection_id_reported(fixtures_dir: Path) -> None:
    repo = DetectionRepository(fixtures_dir / "duplicate-id")
    errors = validate_repository(repo)
    dup_errors = [e for e in errors if e.code == "DEP-DUP-012"]
    assert len(dup_errors) == 1
    assert "detections/endpoint" in dup_errors[0].message
    assert "detections/identity" in dup_errors[0].message


def test_invalid_taxonomy_reported(fixtures_dir: Path) -> None:
    repo = DetectionRepository(fixtures_dir / "invalid-taxonomy")
    errors = validate_repository(repo)
    tax_errors = [e for e in errors if e.code == "DEP-TAX-016"]
    assert len(tax_errors) == 1
    assert "unknown-platform" in tax_errors[0].message


def test_minimal_repository_has_no_errors(fixtures_dir: Path) -> None:
    repo = DetectionRepository(fixtures_dir / "minimal")
    errors = validate_repository(repo)
    assert len(errors) == 0


def test_optional_absent_field_does_not_trigger_fil(fixtures_dir: Path) -> None:
    repo = DetectionRepository(fixtures_dir / "optional-field-absent")
    errors = validate_repository(repo)
    fil_errors = [e for e in errors if e.code == "DEP-FIL-004"]
    assert len(fil_errors) == 0
