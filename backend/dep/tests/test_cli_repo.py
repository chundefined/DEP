"""Integration tests for the `dep` console script repository commands."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures" / "repos"


def _dep_executable() -> Path:
    return Path(sys.executable).with_name("dep")


def test_cli_init_repo_creates_structure(tmp_path: Path) -> None:
    target = tmp_path / "new-repo"
    result = subprocess.run(
        [str(_dep_executable()), "init-repo", str(target)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert (target / ".dep" / "policies.yml").is_file()
    assert (target / "taxonomy" / "layers.yml").is_file()
    assert (target / "detections").is_dir()


def test_cli_init_repo_refuses_to_overwrite(tmp_path: Path) -> None:
    target = tmp_path / "existing-repo"
    target.mkdir()
    (target / "file.txt").write_text("existing")
    result = subprocess.run(
        [str(_dep_executable()), "init-repo", str(target)],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0, result.stdout + result.stderr
    assert "not empty" in result.stderr


def test_cli_validate_repo_valid(fixtures_dir: Path) -> None:
    result = subprocess.run(
        [str(_dep_executable()), "validate-repo", str(fixtures_dir / "valid")],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "0 error(s)" in result.stdout


def test_cli_validate_repo_missing_referenced_file(fixtures_dir: Path) -> None:
    result = subprocess.run(
        [str(_dep_executable()), "validate-repo", str(fixtures_dir / "missing-referenced-file")],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert "DEP-FIL-004" in result.stdout


def test_cli_validate_repo_duplicate_id(fixtures_dir: Path) -> None:
    result = subprocess.run(
        [str(_dep_executable()), "validate-repo", str(fixtures_dir / "duplicate-id")],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert "DEP-DUP-012" in result.stdout


def test_cli_validate_repo_invalid_taxonomy(fixtures_dir: Path) -> None:
    result = subprocess.run(
        [str(_dep_executable()), "validate-repo", str(fixtures_dir / "invalid-taxonomy")],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert "DEP-TAX-016" in result.stdout


def test_cli_validate_repo_minimal(fixtures_dir: Path) -> None:
    result = subprocess.run(
        [str(_dep_executable()), "validate-repo", str(fixtures_dir / "minimal")],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "0 error(s)" in result.stdout


def test_cli_validate_still_works_on_files(fixtures_dir: Path) -> None:
    detection = fixtures_dir / "valid" / "detections" / "identity" / "DET-0001-kerberos-brute-force" / "detection.yml"
    result = subprocess.run(
        [str(_dep_executable()), "validate", str(detection)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "OK" in result.stdout
