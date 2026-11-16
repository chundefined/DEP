"""Tests for branch-based environments (slice 007)."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from dep.environments import (
    EnvironmentConfig,
    EnvironmentConfigError,
    is_protected,
    load_environment_config,
    parse_environment_config,
)
from dep.repo import DetectionRepository, RepositoryLoadError
from dep.taxonomy import TaxonomySet
from dep.validation.repo_validator import SCHEMA_VALIDATOR, validate_repository

FIXTURES = Path(__file__).parent / "fixtures"
VALID = FIXTURES / "repos" / "valid"
DET = "detections/identity/DET-0001-kerberos-brute-force"


@pytest.fixture
def repo_copy(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    shutil.copytree(VALID, root)
    return root


def write_branches(root: Path, branches: dict | None, extra: dict | None = None) -> None:
    doc: dict = {"schema_version": "1.0.0"}
    if branches is not None:
        doc["branches"] = branches
    doc.update(extra or {})
    (root / ".dep/environments.yml").write_text(yaml.safe_dump(doc))


def codes(root: Path) -> list[str]:
    return [e.code for e in validate_repository(DetectionRepository(root))]


# ------------------------------------------------------------------ schema ---

def _impl() -> dict:
    return {
        "id": "IMP-0001-SENTINEL", "platform": "sentinel", "type": "native",
        "status": "active", "enabled": True, "version": "1.0.0",
        "logic": {"language": "kql", "file": "implementations/sentinel/rule.kql"},
    }


def _impl_errors(impl: dict) -> list[str]:
    from jsonschema import Draft202012Validator

    defs = SCHEMA_VALIDATOR.schema["$defs"]
    validator = Draft202012Validator({**defs["implementation"], "$defs": defs})
    return [e.message for e in validator.iter_errors(impl)]


def test_implementation_without_environment_is_valid():
    assert _impl_errors(_impl()) == []


@pytest.mark.parametrize("imp_id,ok", [
    ("IMP-0001-SENTINEL", True),
    ("IMP-0001-SENTINEL-PROD", True),
    ("IMP-0001-SENTINEL-RULE2", True),
    ("sentinel-rule", False),
    ("IMP-1-SENTINEL", False),
])
def test_implementation_id_pattern(imp_id, ok):
    assert (_impl_errors({**_impl(), "id": imp_id}) == []) is ok


def test_implementation_with_environment_fails_schema():
    assert _impl_errors({**_impl(), "environment": "prod"})


# ------------------------------------------------------------ config unit ---

def test_environment_resolution():
    cfg = EnvironmentConfig({"develop": "dev", "main": "prod"})
    assert cfg.environment_for("develop") == "dev"
    assert cfg.environment_for("feature/x") is None
    assert cfg.branch_for("prod") == "main"
    assert cfg.branch_for("staging") is None


@pytest.mark.parametrize("details,expected", [
    ({"prod": {"requires_approval": True}}, True),
    ({"prod": {"requires_approval": False}}, False),
    ({"prod": {}}, False),
    ({}, False),
])
def test_is_protected(details, expected):
    assert is_protected("main", EnvironmentConfig({"main": "prod"}), details) is expected


def test_unmapped_branch_is_not_protected():
    assert not is_protected("feature/x", EnvironmentConfig({"main": "prod"}),
                            {"prod": {"requires_approval": True}})


def test_taxonomy_exposes_requires_approval():
    ts = TaxonomySet(VALID / "taxonomy")
    assert ts.has_environment("prod")
    assert ts.environment_details["prod"]["requires_approval"] is True
    assert ts.environment_details["dev"]["requires_approval"] is False


@pytest.mark.parametrize("raw", [
    None, [], {"schema_version": "1.0.0"}, {"branches": []},
    {"branches": {"main": ""}}, {"branches": {"main": None}}, {"branches": {"": "prod"}},
])
def test_parse_rejects_malformed(raw):
    with pytest.raises(EnvironmentConfigError):
        parse_environment_config(raw)


# --------------------------------------------------------- repo loading ---

def test_valid_fixture_loads_environments():
    repo = DetectionRepository(VALID)
    assert repo.environments.branches == {"develop": "dev", "main": "prod"}


def test_missing_file_is_cfg_020(repo_copy: Path):
    (repo_copy / ".dep/environments.yml").unlink()
    with pytest.raises(RepositoryLoadError) as exc:
        DetectionRepository(repo_copy)
    assert exc.value.code == "DEP-CFG-020" and "environments.yml" in exc.value.message


def test_invalid_yaml_is_cfg_020(repo_copy: Path):
    (repo_copy / ".dep/environments.yml").write_text("branches: [unclosed")
    with pytest.raises(RepositoryLoadError) as exc:
        DetectionRepository(repo_copy)
    assert exc.value.code == "DEP-CFG-020"


def test_missing_branches_key_is_cfg_020(repo_copy: Path):
    write_branches(repo_copy, None)
    with pytest.raises(RepositoryLoadError) as exc:
        DetectionRepository(repo_copy)
    assert exc.value.code == "DEP-CFG-020"


def test_unknown_top_level_keys_are_ignored(repo_copy: Path):
    write_branches(repo_copy, {"main": "prod"}, extra={"targets": {"prod": {"sentinel": "x"}}})
    assert load_environment_config(repo_copy).branches == {"main": "prod"}
    assert codes(repo_copy) == []


# ----------------------------------------------------- repo validation ---

def test_unknown_environment_is_env_002(repo_copy: Path):
    write_branches(repo_copy, {"develop": "qa", "main": "prod"})
    errs = validate_repository(DetectionRepository(repo_copy))
    assert [e.code for e in errs] == ["DEP-ENV-002"]
    assert "develop" in errs[0].message and "qa" in errs[0].message


def test_two_branches_one_environment_is_env_003(repo_copy: Path):
    write_branches(repo_copy, {"develop": "dev", "integration": "dev", "main": "prod"})
    errs = validate_repository(DetectionRepository(repo_copy))
    assert [e.code for e in errs] == ["DEP-ENV-003"]
    assert "develop" in errs[0].message and "integration" in errs[0].message


def test_taxonomy_environment_without_branch_is_fine(repo_copy: Path):
    write_branches(repo_copy, {"main": "prod"})  # dev and staging unmapped
    assert codes(repo_copy) == []


def test_legacy_environment_field_is_single_env_004(repo_copy: Path):
    p = repo_copy / DET / "detection.yml"
    p.write_text(p.read_text().replace(
        "    platform: sentinel\n", "    platform: sentinel\n    environment: prod\n", 1))
    errs = validate_repository(DetectionRepository(repo_copy))
    assert [e.code for e in errs] == ["DEP-ENV-004"]
    assert errs[0].location == "implementations/0/environment"
    assert "branch" in errs[0].message and "environments.yml" in errs[0].message


def test_legacy_field_with_other_unknown_property_keeps_schema_error(repo_copy: Path):
    p = repo_copy / DET / "detection.yml"
    p.write_text(p.read_text().replace(
        "    platform: sentinel\n",
        "    platform: sentinel\n    environment: prod\n    bogus: 1\n", 1))
    found = codes(repo_copy)
    assert found.count("DEP-ENV-004") == 1 and found.count("DEP-SCH-001") == 1


def test_no_legacy_field_no_env_004():
    assert "DEP-ENV-004" not in codes(VALID)


def test_dep_tax_017_is_retired():
    src = (Path(__file__).parents[1] / "dep/validation/repo_validator.py").read_text()
    assert "DEP-TAX-017" not in src


def test_extras_fixture_with_two_platforms_is_valid():
    assert codes(FIXTURES / "repos" / "valid-with-extras") == []


# ------------------------------------------------------------ init-repo ---

def _dep() -> str:
    return str(Path(sys.executable).with_name("dep"))


def test_init_repo_generates_environments_file_and_validates(tmp_path: Path):
    target = tmp_path / "new"
    assert subprocess.run([_dep(), "init-repo", str(target)]).returncode == 0
    cfg = yaml.safe_load((target / ".dep/environments.yml").read_text())
    assert cfg["branches"] == {"develop": "dev", "main": "prod"}
    out = subprocess.run([_dep(), "validate-repo", str(target)], capture_output=True, text=True)
    assert out.returncode == 0, out.stdout + out.stderr
    owners = (target / "CODEOWNERS").read_text()
    assert not re.search(r"implementations/\*/prod", owners)


def test_validate_repo_cli_reports_missing_environments_file(repo_copy: Path):
    (repo_copy / ".dep/environments.yml").unlink()
    out = subprocess.run([_dep(), "validate-repo", str(repo_copy)], capture_output=True, text=True)
    assert out.returncode != 0 and "DEP-CFG-020" in out.stderr
