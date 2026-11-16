"""Tests for `dep commit` (classification, versions, message, and full workflow)."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from dep import gitutil
from dep.cli.commit_cmd import (
    classify_changes,
    classify_path,
    commit_repo,
    compare_versions,
    find_repo_root,
    validate_message,
)
from dep.gitutil import StatusEntry, parse_status

FIXTURE = Path(__file__).parent / "fixtures" / "repos" / "valid"
DET = "detections/identity/DET-0001-kerberos-brute-force"
GOOD = "chore: update repository"


# ---------------------------------------------------------------- helpers ---

def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=root, capture_output=True, text=True, check=True
    ).stdout.strip()


def init_git(root: Path) -> None:
    git(root, "init", "-q")
    git(root, "config", "user.email", "t@example.com")
    git(root, "config", "user.name", "Test")
    git(root, "config", "commit.gpgsign", "false")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    shutil.copytree(FIXTURE, root)
    init_git(root)
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "chore: baseline")
    git(root, "checkout", "-q", "-b", "feature/test")
    return root


def commits(root: Path) -> int:
    return int(git(root, "rev-list", "--count", "HEAD"))


def staged(root: Path) -> str:
    return git(root, "diff", "--cached", "--name-only")


def edit_version(root: Path, version: str) -> None:
    p = root / DET / "detection.yml"
    text = p.read_text()
    p.write_text(text.replace('\nversion: "1.0.0"', f'\nversion: "{version}"', 1))


def touch_query(root: Path) -> None:
    p = root / DET / "implementations/sentinel/rule.kql"
    p.write_text(p.read_text() + "\n// changed\n")


# ------------------------------------------------------------ unit tests ---

@pytest.mark.parametrize("path,expected", [
    (f"{DET}/detection.yml", ("material", DET)),
    (f"{DET}/implementations/qradar/rule.aql", ("material", DET)),
    (f"{DET}/logic/sigma.yml", ("material", DET)),
    (f"{DET}/docs/investigation.md", ("support", DET)),
    (f"{DET}/tests/data/positive.json", ("support", DET)),
    (f"{DET}/validations/index.yml", ("support", DET)),
    ("detections/DET-0009-flat/detection.yml", ("material", "detections/DET-0009-flat")),
    ("taxonomy/layers.yml", ("config", None)),
    (".dep/policies.yml", ("config", None)),
    ("README.md", ("other", None)),
])
def test_classify_path(path, expected):
    assert classify_path(path) == expected


def test_classify_changes_rename_counts_both_paths():
    entry = StatusEntry("R ", f"{DET}-v2/detection.yml", f"{DET}/detection.yml")
    result = classify_changes([entry])
    assert result.material_dirs == {f"{DET}-v2", DET}
    assert result.needs_validation


def test_other_only_skips_validation():
    assert not classify_changes([StatusEntry("??", "README.md")]).needs_validation


def test_parse_status_handles_renames_and_untracked():
    raw = "?? a/b.txt\0 M c.txt\0R  new.txt\0old.txt\0"
    entries = parse_status(raw)
    assert [(e.code, e.path, e.orig_path) for e in entries] == [
        ("??", "a/b.txt", None),
        (" M", "c.txt", None),
        ("R ", "new.txt", "old.txt"),
    ]


@pytest.mark.parametrize("old,new,expected", [
    ("1.0.0", "1.0.0", "same"),
    ("1.0", "1.0.0", "same"),
    ("1.0.0", "1.1.0", "changed"),
    ("1.10.0", "1.9.0", "downgrade"),
    ("v1.0.0", "1.0.1", "changed"),
    ("alpha", "beta", "changed"),
    ("alpha", "alpha", "same"),
])
def test_compare_versions(old, new, expected):
    assert compare_versions(old, new) == expected


@pytest.mark.parametrize("msg,ok", [
    ("tune(DET-0001): exclude loopback", True),
    ("chore: update tooling", True),
    ("breaking(DET-0001)!: change schema", True),
    ("wip: stuff", False),
    ("feat: ", False),
    ("feat()", False),
    ("feat(): x", False),
    ("feat(a b): x", False),
    ("", False),
    ("just text", False),
])
def test_validate_message(msg, ok):
    assert validate_message(msg) is ok


def test_find_repo_root_from_subdir(repo: Path):
    assert find_repo_root(repo / DET / "docs") == repo.resolve()
    assert find_repo_root(repo.parent) is None


# ------------------------------------------------------ integration tests ---

def test_new_detection_is_committed(repo: Path):
    new = repo / "detections/identity/DET-0001-kerberos-brute-force"
    copy = repo / "detections/identity/DET-0002-copy"
    shutil.copytree(new, copy)
    txt = (copy / "detection.yml").read_text().replace("DET-0001", "DET-0002").replace(
        "kerberos-brute-force", "copy")
    (copy / "detection.yml").write_text(txt)
    before = commits(repo)
    rc = commit_repo(repo, message="feat(DET-0002): add copy")
    files = git(repo, "show", "--name-only", "--format=", "HEAD")
    assert rc == 0
    assert commits(repo) == before + 1
    assert "DET-0002-copy/detection.yml" in files


def test_modified_with_bump_commits_without_prompt(repo: Path):
    touch_query(repo)
    edit_version(repo, "1.1.0")
    rc = commit_repo(repo, message="tune(DET-0001): tweak",
                     prompt=lambda _: pytest.fail("should not prompt"))
    assert rc == 0 and commits(repo) == 2


def test_no_bump_declined_aborts_without_staging(repo: Path):
    touch_query(repo)
    rc = commit_repo(repo, message="tune(DET-0001): tweak",
                     prompt=lambda _: "n", is_tty=lambda: True)
    assert rc == 1 and commits(repo) == 1 and staged(repo) == ""


def test_no_bump_accepted_commits(repo: Path):
    touch_query(repo)
    rc = commit_repo(repo, message="tune(DET-0001): tweak",
                     prompt=lambda _: "y", is_tty=lambda: True)
    assert rc == 0 and commits(repo) == 2


def test_no_bump_with_yes_does_not_prompt(repo: Path):
    touch_query(repo)
    rc = commit_repo(repo, message="tune(DET-0001): tweak", assume_yes=True,
                     prompt=lambda _: pytest.fail("should not prompt"))
    assert rc == 0 and commits(repo) == 2


def test_no_bump_without_tty_aborts(repo: Path):
    touch_query(repo)
    rc = commit_repo(repo, message="tune(DET-0001): tweak", is_tty=lambda: False)
    assert rc == 1 and commits(repo) == 1 and staged(repo) == ""


def test_downgrade_requires_confirmation(repo: Path):
    touch_query(repo)
    edit_version(repo, "0.9.0")
    rc = commit_repo(repo, message="fix(DET-0001): x", is_tty=lambda: False)
    assert rc == 1 and commits(repo) == 1


def test_taxonomy_invalid_blocks_commit(repo: Path):
    (repo / "taxonomy/layers.yml").write_text("not: [valid")
    rc = commit_repo(repo, message=GOOD)
    assert rc == 1 and commits(repo) == 1 and staged(repo) == ""


def test_deleting_referenced_doc_blocks_commit(repo: Path):
    (repo / DET / "docs/investigation.md").unlink()
    rc = commit_repo(repo, message="docs(DET-0001): drop doc")
    assert rc == 1 and commits(repo) == 1 and staged(repo) == ""


def test_docs_only_change_commits(repo: Path):
    p = repo / DET / "docs/investigation.md"
    p.write_text(p.read_text() + "\nmore\n")
    rc = commit_repo(repo, message="docs(DET-0001): expand",
                     prompt=lambda _: pytest.fail("should not prompt"))
    assert rc == 0 and commits(repo) == 2


def test_other_only_skips_validation_and_commits(repo: Path, monkeypatch):
    import dep.cli.commit_cmd as mod
    monkeypatch.setattr(mod, "_run_validation", lambda _r: pytest.fail("validated"))
    (repo / "NOTES.md").write_text("hi")
    assert commit_repo(repo, message=GOOD) == 0


def test_invalid_message_flag_does_nothing(repo: Path):
    touch_query(repo)
    assert commit_repo(repo, message="nope") == 1
    assert commits(repo) == 1 and staged(repo) == ""


def test_prompt_message_and_empty_message(repo: Path):
    (repo / "NOTES.md").write_text("hi")
    assert commit_repo(repo, prompt=lambda _: "") == 1 and staged(repo) == ""
    assert commit_repo(repo, prompt=lambda _: GOOD) == 0 and commits(repo) == 2


def test_clean_repo_exits_zero(repo: Path, capsys):
    assert commit_repo(repo, message=GOOD) == 0
    assert "Nothing to commit" in capsys.readouterr().out and commits(repo) == 1


def test_dry_run_changes_nothing(repo: Path):
    (repo / "NOTES.md").write_text("hi")
    assert commit_repo(repo, message=GOOD, dry_run=True) == 0
    assert commits(repo) == 1 and staged(repo) == ""


def test_ignored_files_not_committed(repo: Path):
    (repo / ".gitignore").write_text("secret.txt\n")
    (repo / "secret.txt").write_text("x")
    assert commit_repo(repo, message=GOOD) == 0
    assert "secret.txt" not in git(repo, "show", "--name-only", "--format=", "HEAD")


def test_work_branch_prints_no_environment(repo: Path, capsys):
    (repo / "NOTES.md").write_text("hi")
    assert commit_repo(repo, message=GOOD, dry_run=True) == 0
    assert "Branch: feature/test (no environment)" in capsys.readouterr().out


def test_unprotected_mapped_branch_commits(repo: Path, capsys):
    git(repo, "checkout", "-q", "-b", "develop")
    (repo / "NOTES.md").write_text("hi")
    assert commit_repo(repo, message=GOOD) == 0
    assert "Branch: develop (environment: dev)" in capsys.readouterr().out
    assert commits(repo) == 2


def test_protected_branch_is_refused(repo: Path, capsys):
    git(repo, "checkout", "-q", "main")
    (repo / "NOTES.md").write_text("hi")
    assert commit_repo(repo, message=GOOD) == 1
    err = capsys.readouterr().err
    assert "protected" in err and "pull request" in err
    assert commits(repo) == 1 and staged(repo) == ""


def test_protected_branch_refused_in_dry_run(repo: Path):
    git(repo, "checkout", "-q", "main")
    (repo / "NOTES.md").write_text("hi")
    assert commit_repo(repo, message=GOOD, dry_run=True) == 1
    assert commits(repo) == 1 and staged(repo) == ""


def test_protected_branch_allowed_with_flag(repo: Path):
    git(repo, "checkout", "-q", "main")
    (repo / "NOTES.md").write_text("hi")
    assert commit_repo(repo, message=GOOD, allow_protected=True) == 0
    assert commits(repo) == 2


def test_first_commit_on_protected_branch_is_allowed(tmp_path: Path):
    root = tmp_path / "fresh-main"
    shutil.copytree(FIXTURE, root)
    init_git(root)
    git(root, "checkout", "-q", "-b", "main")
    assert commit_repo(root, message="feat(DET-0001): initial") == 0
    assert commits(root) == 1


def test_no_environments_file_applies_no_policy(repo: Path):
    git(repo, "checkout", "-q", "main")
    (repo / ".dep/environments.yml").unlink()
    (repo / "NOTES.md").write_text("hi")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "chore: drop env file")
    (repo / "NOTES.md").write_text("again")
    assert commit_repo(repo, message=GOOD) == 0


def test_repo_without_head_makes_first_commit(tmp_path: Path):
    root = tmp_path / "fresh"
    shutil.copytree(FIXTURE, root)
    init_git(root)
    assert commit_repo(root, message="feat(DET-0001): initial") == 0
    assert commits(root) == 1


def test_failing_hook_keeps_stage_and_fails(repo: Path):
    hook = repo / ".git/hooks/pre-commit"
    hook.write_text("#!/bin/sh\nexit 1\n")
    hook.chmod(0o755)
    (repo / "NOTES.md").write_text("hi")
    assert commit_repo(repo, message=GOOD) == 1
    assert commits(repo) == 1 and "NOTES.md" in staged(repo)


def test_not_detection_repo(tmp_path: Path):
    assert commit_repo(tmp_path) == 2


def test_not_git_worktree(tmp_path: Path):
    root = tmp_path / "nogit"
    shutil.copytree(FIXTURE, root)
    assert commit_repo(root, message=GOOD) == 2


def test_nested_in_larger_worktree_is_rejected(tmp_path: Path):
    outer = tmp_path / "outer"
    outer.mkdir()
    init_git(outer)
    inner = outer / "inner"
    shutil.copytree(FIXTURE, inner)
    assert commit_repo(inner, message=GOOD) == 2


def test_no_push_or_tag_commands(repo: Path, monkeypatch):
    seen: list[str] = []
    original = gitutil.run_git

    def spy(root, *args, **kw):
        seen.append(args[0])
        return original(root, *args, **kw)

    monkeypatch.setattr(gitutil, "run_git", spy)
    (repo / "NOTES.md").write_text("hi")
    assert commit_repo(repo, message=GOOD) == 0
    assert not {"push", "tag"} & set(seen)


def test_cli_entrypoint_help():
    exe = Path(os.sys.executable).with_name("dep")
    out = subprocess.run([str(exe), "commit", "--help"], capture_output=True, text=True)
    assert out.returncode == 0 and "--dry-run" in out.stdout
