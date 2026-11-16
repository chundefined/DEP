#!/usr/bin/env python3
"""DEP - Entry point for the `dep` command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

from dep.cli.commit_cmd import commit_repo
from dep.cli.new_detection import new_detection
from dep.cli.repo import init_repo, validate_repo
from dep.cli.validate import validate_file


def _resolve_targets(targets: list[str]) -> list[Path]:
    """Expand directories into a sorted list of detection.yml files."""
    files: list[Path] = []
    for target in targets:
        p = Path(target)
        if p.is_dir():
            files.extend(sorted(p.rglob("detection.yml")))
        elif p.is_file():
            files.append(p)
        else:
            print(f"File or directory not found: {target}", file=sys.stderr)
            sys.exit(2)
    return files


def _cmd_validate(args: argparse.Namespace) -> int:
    """Run schema validation against the requested targets."""
    if args.schema:
        schema_path = Path(args.schema)
    else:
        from importlib import resources
        import dep.schemas

        schema_path = resources.files(dep.schemas) / "detection.schema.json"

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)

    files = _resolve_targets(args.targets)
    if not files:
        print("No detection.yml file found", file=sys.stderr)
        return 2

    total_errors = 0
    for f in files:
        print(f"\n{f}")
        n = validate_file(f, validator)
        total_errors += n
        print("  OK" if n == 0 else f"  {n} error(s)")

    print(f"\n{len(files)} file(s), {total_errors} error(s)")
    return 1 if total_errors else 0


def _cmd_init_repo(args: argparse.Namespace) -> int:
    """Run the init-repo command."""
    return init_repo(Path(args.target))


def _cmd_validate_repo(args: argparse.Namespace) -> int:
    """Run the validate-repo command."""
    return validate_repo(Path(args.target))


def _cmd_commit(args: argparse.Namespace) -> int:
    """Run the commit command."""
    return commit_repo(
        Path(args.repo) if args.repo else None,
        message=args.message,
        assume_yes=args.yes,
        dry_run=args.dry_run,
        allow_protected=args.allow_protected,
    )


def _cmd_new_detection(args: argparse.Namespace) -> int:
    """Run the new-detection command."""
    return new_detection(
        args.name,
        platforms=args.platform,
        repo=Path(args.repo) if args.repo else None,
    )


def main() -> int:
    parser = argparse.ArgumentParser(prog="dep", description="Detection Engineering Platform CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser("validate", help="Validate detection.yml files")
    validate_parser.add_argument(
        "targets",
        nargs="+",
        help="detection.yml files or directories to scan",
    )
    validate_parser.add_argument(
        "--schema",
        default=None,
        help="Path to a custom JSON Schema",
    )
    validate_parser.set_defaults(func=_cmd_validate)

    init_repo_parser = subparsers.add_parser(
        "init-repo", help="Scaffold a new detections repository"
    )
    init_repo_parser.add_argument(
        "target",
        help="Directory where the new repository will be created",
    )
    init_repo_parser.set_defaults(func=_cmd_init_repo)

    validate_repo_parser = subparsers.add_parser(
        "validate-repo", help="Validate a whole detections repository"
    )
    validate_repo_parser.add_argument(
        "target",
        help="Root of the detections repository",
    )
    validate_repo_parser.set_defaults(func=_cmd_validate_repo)

    commit_parser = subparsers.add_parser(
        "commit",
        help="Validate the repository and create a Conventional Commits commit",
    )
    commit_parser.add_argument(
        "--repo",
        default=None,
        help="Root of the detections repository (default: searched upward from the current directory)",
    )
    commit_parser.add_argument(
        "-m",
        "--message",
        default=None,
        help="Commit message as type(scope): subject (asked interactively if omitted)",
    )
    commit_parser.add_argument(
        "--yes",
        action="store_true",
        help="Accept the unchanged-version warning without asking",
    )
    commit_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be committed without staging or committing",
    )
    commit_parser.add_argument(
        "--allow-protected",
        action="store_true",
        help="Allow committing on a protected branch (environment with requires_approval)",
    )
    commit_parser.set_defaults(func=_cmd_commit)

    new_detection_parser = subparsers.add_parser(
        "new-detection",
        help="Scaffold a new detection (next DET id, folders and detection.yml template)",
    )
    new_detection_parser.add_argument(
        "name",
        help="Detection name (used as-is in detection.yml; lowercased with '-' in the folder name)",
    )
    new_detection_parser.add_argument(
        "--platform",
        action="append",
        default=None,
        help="Implementation platform from taxonomy/platforms.yml (repeatable, default: sentinel)",
    )
    new_detection_parser.add_argument(
        "--repo",
        default=None,
        help="Root of the detections repository (default: searched upward from the current directory)",
    )
    new_detection_parser.set_defaults(func=_cmd_new_detection)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
