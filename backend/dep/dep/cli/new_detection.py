"""DEP - ``dep new-detection``: scaffold a new detection in a detection repository."""

from __future__ import annotations

import sys
from pathlib import Path

from dep.cli.commit_cmd import find_repo_root
from dep.scaffold import ScaffoldError, create_detection, resolve_platforms


def _err(msg: str) -> None:
    print(msg, file=sys.stderr)


def new_detection(name: str, platforms: list[str] | None = None, repo: Path | None = None) -> int:
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
        resolved = resolve_platforms(root, platforms)
        target = create_detection(root, name, resolved)
    except ScaffoldError as exc:
        _err(f"Error: {exc}")
        return 1

    rel = target.relative_to(root)
    print(f"Created {target.name.split('-', 2)[0]}-{target.name.split('-', 2)[1]}: {rel}")
    print(f"Platforms: {', '.join(p.id for p in resolved)}")
    print("Next steps:")
    print(f"  1. Edit {rel}/detection.yml, the rule file(s) and documentation/overview.md")
    print("  2. dep validate-repo .")
    print("  3. dep commit")
    return 0
