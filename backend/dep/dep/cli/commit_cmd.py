"""DEP - ``dep commit``: validate a detection repository and create a Conventional Commit."""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import yaml

from dep import gitutil
from dep.environments import (
    CONFIG_RELATIVE_PATH,
    EnvironmentConfigError,
    is_protected,
    load_environment_config,
    load_environment_details,
)
from dep.gitutil import GitError, StatusEntry
from dep.repo import DetectionRepository, RepositoryLoadError
from dep.validation.repo_validator import validate_repository

COMMIT_TYPES = (
    "feat", "fix", "tune", "docs", "test", "valid", "find", "deprecate", "chore", "breaking",
)
MESSAGE_FORMAT = "type(scope): subject   (types: " + ", ".join(COMMIT_TYPES) + "; scope optional)"
_MESSAGE_RE = re.compile(r"^(?:%s)(?:\([^()\s]+\))?!?: \S.*$" % "|".join(COMMIT_TYPES))
_VERSION_RE = re.compile(r"^v?(\d+(?:\.\d+)*)$")

MATERIAL_DIRS = ("implementations", "logic")


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #

def validate_message(message: str) -> bool:
    return bool(_MESSAGE_RE.match(message.strip()))


def compare_versions(old: str, new: str) -> str:
    """Return ``same``, ``changed`` or ``downgrade``."""
    if old == new:
        return "same"
    m_old, m_new = _VERSION_RE.match(old), _VERSION_RE.match(new)
    if m_old and m_new:
        a = [int(p) for p in m_old.group(1).split(".")]
        b = [int(p) for p in m_new.group(1).split(".")]
        width = max(len(a), len(b))
        a += [0] * (width - len(a))
        b += [0] * (width - len(b))
        if a == b:
            return "same"
        if b < a:
            return "downgrade"
    return "changed"


def classify_path(path: str) -> tuple[str, str | None]:
    """Return ``(class, detection_dir)`` for a repo-relative POSIX path.

    Classes: material, support, config, other.
    """
    parts = path.split("/")
    if parts[0] in ("taxonomy", ".dep"):
        return "config", None
    if parts[0] != "detections":
        return "other", None
    for i, part in enumerate(parts[1:], start=1):
        if part.startswith("DET-"):
            det_dir = "/".join(parts[: i + 1])
            rest = parts[i + 1 :]
            if rest == ["detection.yml"] or (rest and rest[0] in MATERIAL_DIRS):
                return "material", det_dir
            return "support", det_dir
    return "support", None


@dataclass
class Classification:
    material_dirs: set[str] = field(default_factory=set)
    needs_validation: bool = False
    counts: dict[str, int] = field(default_factory=lambda: {
        "material": 0, "support": 0, "config": 0, "other": 0,
    })


def classify_changes(entries: list[StatusEntry]) -> Classification:
    result = Classification()
    for entry in entries:
        for path in entry.paths:
            cls, det_dir = classify_path(path)
            result.counts[cls] += 1
            if cls != "other":
                result.needs_validation = True
            if cls == "material" and det_dir:
                result.material_dirs.add(det_dir)
    return result


def find_repo_root(start: Path) -> Path | None:
    start = start.resolve()
    for candidate in (start, *start.parents):
        if (candidate / ".dep" / "policies.yml").is_file() and (candidate / "detections").is_dir():
            return candidate
    return None


def _read_version(text: str | None) -> str | None:
    if text is None:
        return None
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return None
    if not isinstance(data, dict) or data.get("version") is None:
        return None
    return str(data["version"])


def version_warnings(root: Path, material_dirs: set[str], head: bool) -> list[str]:
    """Warnings for material detections whose version did not advance vs HEAD."""
    if not head:
        return []
    warnings: list[str] = []
    for det_dir in sorted(material_dirs):
        rel = f"{det_dir}/detection.yml"
        file = root / rel
        if not file.is_file():
            continue
        new = _read_version(file.read_text(encoding="utf-8"))
        old = _read_version(gitutil.show_head_file(root, rel))
        if new is None or old is None:
            continue
        verdict = compare_versions(old, new)
        if verdict == "same":
            warnings.append(f"{det_dir}: version unchanged ({new})")
        elif verdict == "downgrade":
            warnings.append(f"{det_dir}: version downgraded ({old} -> {new})")
    return warnings


# --------------------------------------------------------------------------- #
# Workflow
# --------------------------------------------------------------------------- #

def _err(msg: str) -> None:
    print(msg, file=sys.stderr)


def _run_validation(root: Path) -> bool:
    try:
        repo = DetectionRepository(root)
    except RepositoryLoadError as exc:
        _err(f"{exc.code}  repo  <root>  {exc.message}")
        return False
    errors = validate_repository(repo)
    if errors:
        for err in errors:
            _err(f"  {err}")
        _err(f"Validation failed: {len(errors)} error(s). Nothing was staged.")
        return False
    print(f"Validation OK ({len(repo.detections)} detection(s)).")
    return True


def resolve_branch(root: Path, branch: str) -> tuple[str | None, bool]:
    """Return ``(environment, protected)`` for *branch*; ``(None, False)`` without policy."""
    try:
        config = load_environment_config(root)
    except EnvironmentConfigError as exc:
        if (root / CONFIG_RELATIVE_PATH).is_file():
            _err(f"WARNING: branch policy not applied: {exc.message}")
        return None, False
    environment = config.environment_for(branch)
    protected = is_protected(branch, config, load_environment_details(root))
    return environment, protected


def commit_repo(
    repo: Path | None = None,
    message: str | None = None,
    assume_yes: bool = False,
    dry_run: bool = False,
    allow_protected: bool = False,
    prompt: Callable[[str], str] = input,
    is_tty: Callable[[], bool] = lambda: sys.stdin.isatty(),
) -> int:
    if message is not None and not validate_message(message):
        _err(f"Invalid commit message. Expected: {MESSAGE_FORMAT}")
        return 1

    if repo is None:
        root = find_repo_root(Path.cwd())
    else:
        root = Path(repo).resolve()
        if not ((root / ".dep" / "policies.yml").is_file() and (root / "detections").is_dir()):
            root = None
    if root is None:
        _err("Not a detection repository (missing .dep/policies.yml and detections/).")
        return 2

    try:
        top = gitutil.toplevel(root)
        if top is None:
            _err(f"Not a Git work tree: {root}")
            return 2
        if top != root:
            _err(f"The detection repository must be the root of its Git work tree ({top}).")
            return 2

        branch = gitutil.current_branch(root)
        environment, protected = resolve_branch(root, branch)
        label = f"environment: {environment}" if environment else "no environment"
        print(f"Branch: {branch} ({label})")
        if protected and gitutil.has_head(root) and not allow_protected:
            _err(
                f"Branch '{branch}' is protected (environment '{environment}' requires approval). "
                "Commit on a work branch and open a pull request, or pass --allow-protected."
            )
            return 1

        entries = gitutil.status(root)
        if not entries:
            print("Nothing to commit.")
            return 0

        cls = classify_changes(entries)
        print(
            f"{len(entries)} change(s): {cls.counts['material']} material, "
            f"{cls.counts['support']} detection-support, {cls.counts['config']} config, "
            f"{cls.counts['other']} other"
        )

        if cls.needs_validation and not _run_validation(root):
            return 1

        warnings = version_warnings(root, cls.material_dirs, gitutil.has_head(root))
        if warnings:
            for w in warnings:
                print(f"WARNING: {w}")
            if assume_yes:
                print("Continuing (--yes).")
            elif not is_tty():
                _err("Confirmation required but stdin is not a terminal; use --yes to accept.")
                return 1
            elif prompt("Commit anyway? [y/N]: ").strip().lower() not in ("y", "yes"):
                _err("Aborted. Nothing was staged.")
                return 1

        if message is None:
            try:
                message = prompt("Commit message (type(scope): subject): ").strip()
            except EOFError:
                message = ""
            if not validate_message(message):
                _err(f"Invalid or empty commit message. Expected: {MESSAGE_FORMAT}")
                return 1
        message = message.strip()

        if dry_run:
            print("Dry run: would commit with message:")
            print(f"  {message}")
            for entry in entries:
                print(f"  {entry.code.strip() or '?'} {entry.path}")
            return 0

        gitutil.add_all(root)
        for line in gitutil.staged_summary(root):
            print(f"  {line}")
        short_hash = gitutil.commit(root, message)
    except GitError as exc:
        _err(str(exc))
        return 1

    print(f"Committed {short_hash}: {message}")
    return 0
