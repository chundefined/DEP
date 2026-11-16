"""DEP - Repository-level validation engine.

Takes a loaded `DetectionRepository` and produces a list of `ValidationError`
objects covering schema, referenced files, duplicate IDs, and taxonomy checks.
"""

from __future__ import annotations

import json
from collections import defaultdict
from importlib import resources
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

import dep.schemas
from dep.repo import Detection, DetectionRepository
from dep.taxonomy import TaxonomySet
from dep.validation.errors import ValidationError


def _load_schema() -> Draft202012Validator:
    schema_path = resources.files(dep.schemas) / "detection.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


SCHEMA_VALIDATOR = _load_schema()


def _normalize(node: Any) -> Any:
    """Convert date/datetime values to ISO-8601 strings recursively."""
    import datetime as dt

    if isinstance(node, dict):
        return {k: _normalize(v) for k, v in node.items()}
    if isinstance(node, list):
        return [_normalize(v) for v in node]
    if isinstance(node, dt.datetime):
        return node.isoformat()
    if isinstance(node, dt.date):
        return node.isoformat()
    return node


# Map of error codes to the human-readable path and the taxonomy checker.
TAXONOMY_CHECKS: list[tuple[str, str, callable]] = [
    ("DEP-TAX-013", "severity", lambda ts, v: ts.has_severity(v)),
    ("DEP-TAX-014", "layers", lambda ts, v: ts.has_layer(v)),
    ("DEP-TAX-015", "data_sources", lambda ts, v: ts.has_data_source(v)),
    ("DEP-TAX-016", "implementations", lambda ts, v: ts.has_platform(v)),
    ("DEP-TAX-018", "intent.adversary_behavior", lambda ts, v: ts.has_behavior(v)),
    ("DEP-TAX-019", "governance.owner.team", lambda ts, v: ts.has_owner(v)),
]


def _schema_errors(detection: Detection) -> list[ValidationError]:
    raw = yaml.safe_load(detection.path.read_text(encoding="utf-8"))
    doc = _normalize(raw)
    errors: list[ValidationError] = []
    for err in sorted(SCHEMA_VALIDATOR.iter_errors(doc), key=lambda e: list(e.path)):
        path = list(err.path)
        location = "/".join(str(p) for p in path) or "<root>"
        legacy = _legacy_environment_error(detection, err, path)
        if legacy is not None:
            errors.extend(legacy)
            continue
        errors.append(
            ValidationError(
                code="DEP-SCH-001",
                detection_id=detection.id,
                location=location,
                message=err.message,
            )
        )
    return errors


def _legacy_environment_error(
    detection: Detection, err: Any, path: list[Any]
) -> list[ValidationError] | None:
    """Replace the generic schema error for implementations[].environment.

    Returns None when *err* is not about the legacy field. Other unexpected
    properties on the same object are still reported as a schema error.
    """
    if (
        err.validator != "additionalProperties"
        or len(path) != 2
        or path[0] != "implementations"
        or not isinstance(err.instance, dict)
    ):
        return None
    allowed = err.schema.get("properties", {})
    unexpected = [k for k in err.instance if k not in allowed]
    if "environment" not in unexpected:
        return None
    result = [
        ValidationError(
            code="DEP-ENV-004",
            detection_id=detection.id,
            location=f"implementations/{path[1]}/environment",
            message=(
                "'environment' is no longer allowed on implementations: the environment "
                "is determined by the Git branch (see .dep/environments.yml). Remove the field."
            ),
        )
    ]
    others = [k for k in unexpected if k != "environment"]
    if others:
        listed = ", ".join(repr(k) for k in others)
        result.append(
            ValidationError(
                code="DEP-SCH-001",
                detection_id=detection.id,
                location="/".join(str(p) for p in path),
                message=f"Additional properties are not allowed ({listed} unexpected)",
            )
        )
    return result


def _referenced_file_errors(detection: Detection) -> list[ValidationError]:
    """Check every present path field resolves to an existing file."""
    errors: list[ValidationError] = []
    base_dir = detection.path.parent
    data = detection.data

    # Implementation logic files and exclusions.
    for idx, impl in enumerate(data.get("implementations", [])):
        logic = impl.get("logic", {})
        if "file" in logic:
            path = base_dir / logic["file"]
            if not path.is_file():
                errors.append(
                    ValidationError(
                        code="DEP-FIL-004",
                        detection_id=detection.id,
                        location=f"implementations/{idx}/logic/file",
                        message=str(path.relative_to(base_dir)),
                    )
                )
        if "exclusions_file" in logic:
            path = base_dir / logic["exclusions_file"]
            if not path.is_file():
                errors.append(
                    ValidationError(
                        code="DEP-FIL-004",
                        detection_id=detection.id,
                        location=f"implementations/{idx}/logic/exclusions_file",
                        message=str(path.relative_to(base_dir)),
                    )
                )

    # Canonical Sigma logic.
    sigma = data.get("sigma", {})
    if isinstance(sigma, dict) and "file" in sigma:
        path = base_dir / sigma["file"]
        if not path.is_file():
            errors.append(
                ValidationError(
                    code="DEP-FIL-004",
                    detection_id=detection.id,
                    location="sigma/file",
                    message=str(path.relative_to(base_dir)),
                )
            )

    # Test data files.
    for idx, test in enumerate(data.get("tests", [])):
        if "data" in test:
            path = base_dir / test["data"]
            if not path.is_file():
                errors.append(
                    ValidationError(
                        code="DEP-FIL-004",
                        detection_id=detection.id,
                        location=f"tests/{idx}/data",
                        message=str(path.relative_to(base_dir)),
                    )
                )

    # Documentation paths.
    documentation = data.get("documentation", {})
    for key, value in documentation.items():
        if key == "references" or not isinstance(value, str):
            continue
        path = base_dir / value
        if not path.is_file():
            errors.append(
                ValidationError(
                    code="DEP-FIL-004",
                    detection_id=detection.id,
                    location=f"documentation/{key}",
                    message=str(path.relative_to(base_dir)),
                )
            )

    # Exception expression files.
    for idx, exc in enumerate(data.get("exceptions", [])):
        if "expression_file" in exc:
            path = base_dir / exc["expression_file"]
            if not path.is_file():
                errors.append(
                    ValidationError(
                        code="DEP-FIL-004",
                        detection_id=detection.id,
                        location=f"exceptions/{idx}/expression_file",
                        message=str(path.relative_to(base_dir)),
                    )
                )

    # Validation runs index.
    validation = data.get("validation", {})
    if isinstance(validation, dict) and "runs_index" in validation:
        path = base_dir / validation["runs_index"]
        if not path.is_file():
            errors.append(
                ValidationError(
                    code="DEP-FIL-004",
                    detection_id=detection.id,
                    location="validation/runs_index",
                    message=str(path.relative_to(base_dir)),
                )
            )

    return errors


def _taxonomy_errors(detection: Detection, taxonomies: TaxonomySet) -> list[ValidationError]:
    errors: list[ValidationError] = []
    data = detection.data

    severity = data.get("severity")
    if isinstance(severity, str) and not taxonomies.has_severity(severity):
        errors.append(
            ValidationError(
                code="DEP-TAX-013",
                detection_id=detection.id,
                location="severity",
                message=f"'{severity}' not found in taxonomy/severity.yml",
            )
        )

    for idx, layer in enumerate(data.get("layers", [])):
        layer_id = layer.get("id")
        if isinstance(layer_id, str) and not taxonomies.has_layer(layer_id):
            errors.append(
                ValidationError(
                    code="DEP-TAX-014",
                    detection_id=detection.id,
                    location=f"layers/{idx}/id",
                    message=f"'{layer_id}' not found in taxonomy/layers.yml",
                )
            )

    for idx, ds in enumerate(data.get("data_sources", [])):
        ds_id = ds.get("id")
        if isinstance(ds_id, str) and not taxonomies.has_data_source(ds_id):
            errors.append(
                ValidationError(
                    code="DEP-TAX-015",
                    detection_id=detection.id,
                    location=f"data_sources/{idx}/id",
                    message=f"'{ds_id}' not found in taxonomy/data-sources.yml",
                )
            )

    for idx, impl in enumerate(data.get("implementations", [])):
        platform = impl.get("platform")
        if isinstance(platform, str) and not taxonomies.has_platform(platform):
            errors.append(
                ValidationError(
                    code="DEP-TAX-016",
                    detection_id=detection.id,
                    location=f"implementations/{idx}/platform",
                    message=f"'{platform}' not found in taxonomy/platforms.yml",
                )
            )

    intent = data.get("intent", {})
    for idx, behavior in enumerate(intent.get("adversary_behavior", [])):
        if isinstance(behavior, str) and not taxonomies.has_behavior(behavior):
            errors.append(
                ValidationError(
                    code="DEP-TAX-018",
                    detection_id=detection.id,
                    location=f"intent/adversary_behavior/{idx}",
                    message=f"'{behavior}' not found in taxonomy/behaviors.yml",
                )
            )

    governance = data.get("governance", {})
    owner = governance.get("owner", {})
    team = owner.get("team")
    if isinstance(team, str) and not taxonomies.has_owner(team):
        errors.append(
            ValidationError(
                code="DEP-TAX-019",
                detection_id=detection.id,
                location="governance/owner/team",
                message=f"'{team}' not found in taxonomy/owners.yml",
            )
        )

    return errors


def _duplicate_id_errors(detections: list[Detection], repo_root: Path) -> list[ValidationError]:
    ids: dict[str, list[Path]] = defaultdict(list)
    for detection in detections:
        ids[detection.id].append(detection.path)

    errors: list[ValidationError] = []
    for detection_id, paths in ids.items():
        if len(paths) > 1:
            rel_paths = ", ".join(
                str(p.relative_to(repo_root)) for p in paths
            )
            errors.append(
                ValidationError(
                    code="DEP-DUP-012",
                    detection_id="repo",
                    location=detection_id,
                    message=rel_paths,
                )
            )
    return errors


def _environment_errors(repo: DetectionRepository) -> list[ValidationError]:
    errors: list[ValidationError] = []
    by_env: dict[str, list[str]] = defaultdict(list)
    for branch, env in repo.environments.branches.items():
        by_env[env].append(branch)
        if not repo.taxonomies.has_environment(env):
            errors.append(
                ValidationError(
                    code="DEP-ENV-002",
                    detection_id="repo",
                    location=f"branches/{branch}",
                    message=f"branch '{branch}' maps to '{env}', not found in taxonomy/environments.yml",
                )
            )
    for env, branches in by_env.items():
        if len(branches) > 1:
            errors.append(
                ValidationError(
                    code="DEP-ENV-003",
                    detection_id="repo",
                    location=env,
                    message=f"environment '{env}' is mapped by more than one branch: {', '.join(branches)}",
                )
            )
    return errors


def validate_repository(repo: DetectionRepository) -> list[ValidationError]:
    """Validate a loaded repository and return all found errors."""
    errors: list[ValidationError] = []

    # Cross-detection checks.
    errors.extend(_duplicate_id_errors(repo.detections, repo.root))
    errors.extend(_environment_errors(repo))

    # Per-detection checks.
    for detection in repo.detections:
        errors.extend(_schema_errors(detection))
        errors.extend(_referenced_file_errors(detection))
        errors.extend(_taxonomy_errors(detection, repo.taxonomies))

    return errors
