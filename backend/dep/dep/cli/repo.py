"""DEP - CLI handlers for repository-level commands (`init-repo`, `validate-repo`)."""

from __future__ import annotations

import shutil
import sys
from importlib import resources
from pathlib import Path

import dep.templates.repo as repo_template
from dep.repo import DetectionRepository, RepositoryLoadError
from dep.validation.repo_validator import validate_repository


_TEMPLATE_ROOT = resources.files(repo_template)


def _copy_template(src: resources.abc.Traversable, dst: Path) -> None:
    """Recursively copy a template resource tree into the filesystem."""
    if src.is_file():
        dst.parent.mkdir(parents=True, exist_ok=True)
        # .gitkeep files may be empty resources; write bytes manually.
        with resources.as_file(src) as src_path:
            shutil.copy2(src_path, dst)
    else:
        dst.mkdir(parents=True, exist_ok=True)
        for child in src.iterdir():
            _copy_template(child, dst / child.name)


def init_repo(target: Path) -> int:
    """Scaffold a new detection content repository at *target*."""
    target = Path(target)
    if target.exists() and any(target.iterdir()):
        print(
            f"Error: target directory is not empty: {target}",
            file=sys.stderr,
        )
        return 1

    target.mkdir(parents=True, exist_ok=True)
    _copy_template(_TEMPLATE_ROOT, target)
    print(f"Repository initialized at: {target}")
    return 0


def validate_repo(target: Path) -> int:
    """Validate a detection content repository at *target*."""
    target = Path(target)
    try:
        repo = DetectionRepository(target)
    except RepositoryLoadError as exc:
        print(f"{exc.code}  repo  <root>  {exc.message}", file=sys.stderr)
        return 2

    errors = validate_repository(repo)

    for detection in repo.detections:
        rel_path = detection.path.relative_to(repo.root)
        print(f"\n{rel_path}")
        detection_errors = [e for e in errors if e.detection_id == detection.id]
        if not detection_errors:
            print("  OK")
        else:
            for err in detection_errors:
                print(f"  {err}")

    cross_errors = [e for e in errors if e.detection_id == "repo"]
    if cross_errors:
        print("\n[repository errors]")
        for err in cross_errors:
            print(f"  {err}")

    if not errors:
        print(f"\n{len(repo.detections)} detection(s), 0 error(s)")
        return 0

    print(
        f"\n{len(repo.detections)} detection(s), {len(errors)} error(s)",
        file=sys.stderr,
    )
    return 1
