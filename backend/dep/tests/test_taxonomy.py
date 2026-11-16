"""Unit tests for taxonomy loading."""

from __future__ import annotations

from pathlib import Path

import pytest

from dep.taxonomy import TaxonomyLoadError, TaxonomySet


@pytest.fixture
def template_taxonomy_dir() -> Path:
    return Path(__file__).parent / "fixtures" / "repos" / "valid" / "taxonomy"


def test_loads_all_taxonomies(template_taxonomy_dir: Path) -> None:
    ts = TaxonomySet(template_taxonomy_dir)
    assert ts.has_platform("sentinel")
    assert ts.has_environment("prod")
    assert ts.has_layer("identity")
    assert ts.has_data_source("windows-security-events")
    assert ts.has_behavior("brute-force")
    assert ts.has_owner("detection-engineering")
    assert ts.has_severity("high")


def test_unknown_values_return_false(template_taxonomy_dir: Path) -> None:
    ts = TaxonomySet(template_taxonomy_dir)
    assert not ts.has_platform("unknown-siem")
    assert not ts.has_layer("unknown-layer")


def test_missing_taxonomy_file_raises(tmp_path: Path) -> None:
    taxonomy_dir = tmp_path / "taxonomy"
    taxonomy_dir.mkdir()
    (taxonomy_dir / "platforms.yml").write_text("platforms:\n  sentinel:\n")
    with pytest.raises(TaxonomyLoadError) as exc_info:
        TaxonomySet(taxonomy_dir)
    assert exc_info.value.code == "DEP-CFG-020"
    assert "Required taxonomy file missing" in exc_info.value.message


def test_malformed_yaml_raises(tmp_path: Path) -> None:
    taxonomy_dir = tmp_path / "taxonomy"
    taxonomy_dir.mkdir()
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
        (taxonomy_dir / filename).write_text(f"{filename.replace('-', '_').replace('.yml', '')}:\n  x:\n")
    (taxonomy_dir / "platforms.yml").write_text("platforms: [not a mapping")
    with pytest.raises(TaxonomyLoadError) as exc_info:
        TaxonomySet(taxonomy_dir)
    assert exc_info.value.code == "DEP-CFG-020"
    assert "Malformed YAML" in exc_info.value.message


def test_attack_directory_is_ignored(template_taxonomy_dir: Path) -> None:
    # The template includes taxonomy/attack/.gitkeep; the loader should not fail.
    ts = TaxonomySet(template_taxonomy_dir)
    assert "attack" not in ts.platforms
