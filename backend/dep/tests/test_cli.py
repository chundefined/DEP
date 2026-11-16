"""Integration tests for the `dep` console script."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures"


def _dep_executable() -> Path:
    return Path(sys.executable).with_name("dep")


def test_cli_valid_fixture(fixtures_dir: Path) -> None:
    result = subprocess.run(
        [str(_dep_executable()), "validate", str(fixtures_dir / "valid" / "minimal.yml")],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "OK" in result.stdout


def test_cli_invalid_fixture(fixtures_dir: Path) -> None:
    result = subprocess.run(
        [str(_dep_executable()), "validate", str(fixtures_dir / "invalid" / "missing-id.yml")],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert "DEP-SCH-001" in result.stdout
