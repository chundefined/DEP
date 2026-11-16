"""Unit tests for dep.scaffold (slugs, ids, platforms, template rendering)."""

from __future__ import annotations

from importlib import resources
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

import dep.schemas
import dep.templates.detection as detection_template
from dep.cli.repo import init_repo
from dep.scaffold import (
    Platform,
    ScaffoldError,
    create_detection,
    next_detection_id,
    render_detection,
    resolve_platforms,
    slugify,
)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    target = tmp_path / "repo"
    assert init_repo(target) == 0
    return target


@pytest.mark.parametrize(
    "name, expected",
    [
        ("Kerberos Brute Force", "kerberos-brute-force"),
        ("Kerberos   Brute \t Force", "kerberos-brute-force"),
        ("Admin Login (Failed)!", "admin-login-failed"),
        ("  --a--b--  ", "a-b"),
        ("Already-Slug", "already-slug"),
    ],
)
def test_slugify(name: str, expected: str) -> None:
    assert slugify(name) == expected


def test_slugify_empty_result() -> None:
    with pytest.raises(ScaffoldError):
        slugify("!!! ???")


def _make(detections: Path, folder: str, det_id: str | None = None) -> None:
    path = detections / folder
    path.mkdir(parents=True)
    if det_id:
        (path / "detection.yml").write_text(f"id: {det_id}\n", encoding="utf-8")


def test_next_id_empty(tmp_path: Path) -> None:
    (tmp_path / "detections").mkdir()
    assert next_detection_id(tmp_path / "detections") == "DET-0001"


def test_next_id_highest_and_gaps(tmp_path: Path) -> None:
    d = tmp_path / "detections"
    _make(d, "DET-0001-a")
    _make(d, "DET-0003-c")
    assert next_detection_id(d) == "DET-0004"


def test_next_id_uses_detection_yml(tmp_path: Path) -> None:
    d = tmp_path / "detections"
    _make(d, "renamed-folder", "DET-0010")
    assert next_detection_id(d) == "DET-0011"


def test_next_id_ignores_malformed_yaml(tmp_path: Path) -> None:
    d = tmp_path / "detections"
    _make(d, "DET-0002-x")
    (d / "DET-0002-x" / "detection.yml").write_text("id: [unclosed\n", encoding="utf-8")
    assert next_detection_id(d) == "DET-0003"


def test_next_id_grows_beyond_four_digits(tmp_path: Path) -> None:
    d = tmp_path / "detections"
    _make(d, "DET-9999-x")
    assert next_detection_id(d) == "DET-10000"


def test_resolve_platforms_default(repo: Path) -> None:
    assert resolve_platforms(repo, None) == [Platform("sentinel", "kql")]


def test_resolve_platforms_multiple_dedup(repo: Path) -> None:
    result = resolve_platforms(repo, ["qradar", "sentinel", "qradar"])
    assert [p.id for p in result] == ["qradar", "sentinel"]
    assert result[0].extension == "aql"


def test_resolve_platforms_unknown(repo: Path) -> None:
    with pytest.raises(ScaffoldError, match="Available platforms"):
        resolve_platforms(repo, ["foo"])


def test_platform_suffix_replaces_underscore() -> None:
    assert Platform("sentinel_one", "fql").suffix == "SENTINEL-ONE"


def test_templates_readable_through_resources() -> None:
    root = resources.files(detection_template)
    for name in ("detection.yml", "implementation.yml", "log_source.yml", "rule.txt", "overview.md"):
        assert (root / name).read_text(encoding="utf-8").strip()


def test_render_preserves_special_name() -> None:
    name = "Brute: force # test"
    text = render_detection("DET-0005", name, [Platform("sentinel", "kql")])
    doc = yaml.safe_load(text)
    assert doc["name"] == name
    assert doc["implementations"][0]["id"] == "IMP-0005-SENTINEL"
    assert doc["implementations"][0]["logic"]["file"] == "implementations/sentinel/rule.kql"


def test_rendered_template_matches_schema() -> None:
    import json

    schema = json.loads((resources.files(dep.schemas) / "detection.schema.json").read_text("utf-8"))
    validator = Draft202012Validator(schema)
    text = render_detection(
        "DET-0005", "Example", [Platform("sentinel", "kql"), Platform("sentinel_one", "fql")]
    )
    doc = yaml.safe_load(text)
    assert list(validator.iter_errors(doc)) == []
    assert "| where" not in text
    assert "/Users/" not in text


def test_create_name_too_short_creates_nothing(repo: Path) -> None:
    with pytest.raises(ScaffoldError):
        create_detection(repo, "ab", [Platform("sentinel", "kql")])
    assert list((repo / "detections").glob("DET-*")) == []


def test_create_target_exists(repo: Path) -> None:
    target = repo / "detections" / "DET-0001-x"
    create_detection(repo, "x y", [Platform("sentinel", "kql")])
    assert (repo / "detections" / "DET-0001-x-y").is_dir()
    # a second call allocates a new id and never overwrites
    second = create_detection(repo, "x y", [Platform("sentinel", "kql")])
    assert second.name == "DET-0002-x-y"
    assert not target.exists()
