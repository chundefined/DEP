"""Unit tests for repository loading."""

from __future__ import annotations

from pathlib import Path

import pytest

from dep.repo import DetectionRepository, RepositoryLoadError


@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures" / "repos"


def test_loads_valid_repository(fixtures_dir: Path) -> None:
    repo = DetectionRepository(fixtures_dir / "valid")
    assert repo.root == (fixtures_dir / "valid").resolve()
    assert len(repo.detections) == 1
    assert repo.detections[0].id == "DET-0001"
    assert "validation_policy" in repo.policies
    assert repo.taxonomies.has_platform("sentinel")


def test_loads_repository_with_zero_detections(fixtures_dir: Path) -> None:
    repo = DetectionRepository(fixtures_dir / "minimal")
    assert len(repo.detections) == 0


def test_missing_policies_file_raises(tmp_path: Path) -> None:
    (tmp_path / "taxonomy").mkdir()
    (tmp_path / "detections").mkdir()
    with pytest.raises(RepositoryLoadError) as exc_info:
        DetectionRepository(tmp_path)
    assert exc_info.value.code == "DEP-CFG-020"
    assert ".dep/policies.yml" in exc_info.value.message


def test_missing_detections_directory_raises(tmp_path: Path) -> None:
    (tmp_path / ".dep").mkdir()
    (tmp_path / ".dep" / "policies.yml").write_text("schema_version: '1.0.0'\n")
    (tmp_path / "taxonomy").mkdir()
    for filename in [
        "platforms.yml",
        "environments.yml",
        "layers.yml",
        "data-sources.yml",
        "log-sources.yml",
        "behaviors.yml",
        "owners.yml",
        "severity.yml",
        "scoring.yml",
    ]:
        (tmp_path / "taxonomy" / filename).write_text(f"{filename.replace('-', '_').replace('.yml', '')}:\n  x:\n")
    with pytest.raises(RepositoryLoadError) as exc_info:
        DetectionRepository(tmp_path)
    assert exc_info.value.code == "DEP-CFG-020"
    assert "detections" in exc_info.value.message
