"""Integration tests for `dep new-detection`."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


def _dep() -> str:
    return str(Path(sys.executable).with_name("dep"))


def _run(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run([_dep(), *args], capture_output=True, text=True, cwd=cwd)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    target = tmp_path / "repo"
    assert _run("init-repo", str(target)).returncode == 0
    return target


def test_scaffold_validates_and_allocates_sequential_ids(repo: Path) -> None:
    first = _run("new-detection", "Kerberos Brute Force", "--repo", str(repo))
    assert first.returncode == 0, first.stderr
    assert "DET-0001" in first.stdout
    assert "detections/DET-0001-kerberos-brute-force" in first.stdout
    second = _run("new-detection", "Second Rule", "--repo", str(repo))
    assert "DET-0002" in second.stdout
    base = repo / "detections" / "DET-0001-kerberos-brute-force"
    assert (base / "detection.yml").is_file()
    assert (base / "implementations" / "sentinel" / "rule.kql").is_file()
    assert (base / "documentation" / "overview.md").is_file()
    result = _run("validate-repo", str(repo))
    assert result.returncode == 0, result.stdout + result.stderr
    assert "2 detection(s), 0 error(s)" in result.stdout


@pytest.mark.parametrize("platform, rule", [("qradar", "rule.aql"), ("splunk", "rule.spl"), ("sentinel_one", "rule.fql")])
def test_explicit_platform_validates(repo: Path, platform: str, rule: str) -> None:
    result = _run("new-detection", "Example", "--platform", platform, "--repo", str(repo))
    assert result.returncode == 0, result.stderr
    base = repo / "detections" / "DET-0001-example"
    assert (base / "implementations" / platform / rule).is_file()
    assert not (base / "implementations" / "sentinel").exists()
    assert _run("validate-repo", str(repo)).returncode == 0


def test_multiple_platforms(repo: Path) -> None:
    result = _run("new-detection", "Example", "--platform", "sentinel", "--platform", "qradar", "--repo", str(repo))
    assert result.returncode == 0, result.stderr
    base = repo / "detections" / "DET-0001-example" / "implementations"
    assert (base / "sentinel" / "rule.kql").is_file()
    assert (base / "qradar" / "rule.aql").is_file()
    assert _run("validate-repo", str(repo)).returncode == 0


def test_unknown_platform_creates_nothing(repo: Path) -> None:
    result = _run("new-detection", "Example", "--platform", "foo", "--repo", str(repo))
    assert result.returncode == 1
    assert "Available platforms" in result.stderr
    assert list((repo / "detections").glob("DET-*")) == []


def test_run_from_nested_directory(repo: Path) -> None:
    nested = repo / "docs" / "runbooks"
    result = _run("new-detection", "Nested Run", cwd=nested)
    assert result.returncode == 0, result.stderr
    assert (repo / "detections" / "DET-0001-nested-run" / "detection.yml").is_file()


def test_not_a_detection_repository(tmp_path: Path) -> None:
    result = _run("new-detection", "Example", cwd=tmp_path)
    assert result.returncode == 2
    assert "Not a detection repository" in result.stderr


def test_invalid_names(repo: Path) -> None:
    assert _run("new-detection", "!!!", "--repo", str(repo)).returncode == 1
    assert _run("new-detection", "ab", "--repo", str(repo)).returncode == 1
    assert list((repo / "detections").glob("DET-*")) == []


def test_missing_name_is_usage_error(repo: Path) -> None:
    assert _run("new-detection", "--repo", str(repo)).returncode == 2


def test_no_git_side_effects(repo: Path) -> None:
    subprocess.run(["git", "init", "-q", "-b", "develop"], cwd=repo, check=True)
    assert _run("new-detection", "Example", "--repo", str(repo)).returncode == 0
    status = subprocess.run(["git", "status", "--porcelain"], cwd=repo, capture_output=True, text=True).stdout
    assert "?? detections/" in status
    log = subprocess.run(["git", "log"], cwd=repo, capture_output=True, text=True)
    assert log.returncode != 0 or log.stdout.strip() == ""


def test_special_characters_in_name(repo: Path) -> None:
    result = _run("new-detection", "Brute: force # (x)", "--repo", str(repo))
    assert result.returncode == 0, result.stderr
    assert (repo / "detections" / "DET-0001-brute-force-x" / "detection.yml").is_file()
    assert _run("validate-repo", str(repo)).returncode == 0
