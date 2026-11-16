"""DEP - Thin wrapper over the system ``git`` executable.

Kept free of CLI and detection knowledge so other commands can reuse it.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


class GitError(Exception):
    """Raised when a git command fails or git is unavailable."""


@dataclass(frozen=True)
class StatusEntry:
    """One entry of ``git status --porcelain=v1 -z``."""

    code: str
    path: str
    orig_path: str | None = None

    @property
    def paths(self) -> list[str]:
        return [self.path] + ([self.orig_path] if self.orig_path else [])


def run_git(root: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    if shutil.which("git") is None:
        raise GitError("git executable not found in PATH")
    proc = subprocess.run(
        ["git", *args],
        cwd=str(root),
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if check and proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip()
        raise GitError(f"git {' '.join(args)} failed: {detail}")
    return proc


def toplevel(path: Path) -> Path | None:
    """Return the work tree top level containing *path*, or None."""
    proc = run_git(path, "rev-parse", "--show-toplevel", check=False)
    if proc.returncode != 0:
        return None
    return Path(proc.stdout.strip()).resolve()


def current_branch(root: Path) -> str:
    proc = run_git(root, "symbolic-ref", "--short", "-q", "HEAD", check=False)
    name = proc.stdout.strip()
    return name or "(detached HEAD)"


def has_head(root: Path) -> bool:
    return run_git(root, "rev-parse", "--verify", "-q", "HEAD", check=False).returncode == 0


def parse_status(raw: str) -> list[StatusEntry]:
    """Parse NUL-separated porcelain v1 output, handling rename/copy pairs."""
    fields = raw.split("\0")
    entries: list[StatusEntry] = []
    i = 0
    while i < len(fields):
        field = fields[i]
        i += 1
        if len(field) < 4:
            continue
        code, path = field[:2], field[3:]
        orig = None
        if "R" in code or "C" in code:
            orig = fields[i] if i < len(fields) else None
            i += 1
        entries.append(StatusEntry(code=code, path=path, orig_path=orig))
    return entries


def status(root: Path) -> list[StatusEntry]:
    proc = run_git(root, "status", "--porcelain=v1", "-z", "-uall")
    return parse_status(proc.stdout)


def show_head_file(root: Path, rel_path: str) -> str | None:
    """Return the content of *rel_path* at HEAD, or None if unavailable."""
    proc = run_git(root, "show", f"HEAD:{rel_path}", check=False)
    return proc.stdout if proc.returncode == 0 else None


def add_all(root: Path) -> None:
    run_git(root, "add", "-A")


def staged_summary(root: Path) -> list[str]:
    proc = run_git(root, "diff", "--cached", "--name-status")
    return [line for line in proc.stdout.splitlines() if line.strip()]


def commit(root: Path, message: str) -> str:
    """Create a commit and return its short hash."""
    run_git(root, "commit", "-m", message)
    return run_git(root, "rev-parse", "--short", "HEAD").stdout.strip()
