# dep - Detection Engineering Platform CLI

Command-line tool to scaffold, validate, version and commit cybersecurity detections (detection-as-code) in a Git repository.

> The PostgreSQL loading and the read API are designed in `docs/` but are not part of this repository yet.

For a non-technical introduction to the project (what it is, how a detections repository is organized, usage examples), read the [root README](../../README.md). This document covers the technical details of the CLI.

## Requirements

- Python 3.10 or higher
- Git available in `PATH`

## Local setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e ".[test]"
pytest
```

## Commands

| Command | Description |
|---|---|
| `dep validate <path>...` | Validate one or more `detection.yml` files (or directories) against the JSON Schema. Structure only. |
| `dep validate-repo <path>` | Validate a whole detections repository: schema, taxonomies, policies, referenced files, duplicate IDs and the environments configuration. |
| `dep init-repo <path>` | Create the structure of a new detections repository (must target an empty or non-existing directory). |
| `dep new-detection <name> [--platform <id>]... [--repo <path>]` | Scaffold a new detection with the next `DET-NNNN` id, its folders and a standard `detection.yml` template. |
| `dep commit [options]` | Validate the repository, warn if a detection changed without bumping its `version`, and create a Conventional Commits commit. |

Exit codes: `0` success, `1` validation or workflow failure, `2` usage or repository error (for example, not a detections repository).

### `dep new-detection`

```
dep new-detection <name> [--platform <id>]... [--repo <path>]
```

| Option | Description |
|---|---|
| `<name>` | Detection name (at least 3 characters). Used as typed in `detection.yml`. The folder is `detections/DET-<NEXTID>-<slug>`, where the slug is the name in lowercase with whitespace replaced by `-` (other unsafe characters are dropped). |
| `--platform <id>` | Platform of the implementation, taken from `taxonomy/platforms.yml`. Repeatable. Default: `sentinel`. The rule file is `implementations/<id>/rule.<ext>` (`kql`, `aql`, `spl`, `lucene`, `fql`). |
| `--repo <path>` | Repository root (default: searched upward from the current directory). |

The next id is the highest `DET-NNNN` found in folder names and in `detection.yml` files, plus one. The command never overwrites files, does not stage or commit, and a fresh detection passes `dep validate-repo` in a repository created by `init-repo`. Exit codes: `0` success, `1` invalid name, unknown platform or existing target, `2` not a detections repository.

Generated structure (default platform):

```
detections/DET-0001-kerberos-brute-force/
  detection.yml                       standard template with TODO markers
  implementations/sentinel/rule.kql   placeholder query
  documentation/overview.md           placeholder document
```

The generated `detection.yml` follows the standard used by existing detections: required fields plus `confidence`, `intent` (hypothesis, attack surface, scope), `mitre`, `layers`, `data_sources` with `log_sources`, `implementations` (schedule, entity mappings, suppression, threshold, notes), `source` and `governance.owner`. Optional blocks (`enrichment_assets`, `tests`, `threat`, `exceptions`, `relationships`, `sigma`) appear commented. `mitre` uses the placeholders `TA0000` / `T0000`: replace them.

Examples:

```bash
dep new-detection "Kerberos Brute Force"                                  # sentinel (default)
dep new-detection "Kerberos Brute Force" --platform qradar                # qradar only
dep new-detection "Kerberos Brute Force" --platform sentinel --platform qradar
dep new-detection "Kerberos Brute Force" --repo /path/to/detections-repo
```

### `dep commit`

```
dep commit [--repo <path>] [-m "<type(scope): subject>"] [--yes] [--dry-run] [--allow-protected]
```

| Option | Description |
|---|---|
| `--repo <path>` | Root of the detections repository. By default it is searched upward from the current directory (markers: `.dep/policies.yml` and `detections/`). The root must be the top level of its Git work tree. |
| `-m`, `--message` | Commit message as `type(scope): subject`. If omitted, it is asked interactively. It is validated before anything else. |
| `--yes` | Accept the unchanged-version warning without asking (needed when stdin is not a terminal). |
| `--dry-run` | Show the plan (branch, change summary, validation, message) without staging or committing. |
| `--allow-protected` | Allow committing on a protected branch. |

Allowed commit types: `feat`, `fix`, `tune`, `docs`, `test`, `valid`, `find`, `deprecate`, `chore`, `breaking`. The scope is optional and cannot be empty or contain spaces.

Workflow, in order:

1. Validate the message format (when given with `-m`).
2. Resolve the repository root and the current branch, and apply the branch policy.
3. Read and classify the changes (material, detection-support, config, other).
4. Run `validate-repo` when anything under `detections/`, `taxonomy/` or `.dep/` changed. On errors, abort without staging.
5. For detections with material changes (`detection.yml`, `implementations/`, `logic/`), compare `version` with `HEAD`. If unchanged (or lower), warn and ask for confirmation once.
6. Stage everything (`git add -A`) and create the commit. The commit hash is printed.

`dep commit` never pushes, never creates tags, never bumps versions and never bypasses Git hooks. If a hook rejects the commit, the changes stay staged.

Examples:

```bash
cd /path/to/your-detections-repo
dep commit --dry-run -m "tune(DET-0001): exclude loopback NOUSER"   # only show the plan
dep commit                                                          # ask for the message
dep commit -m "feat(DET-0004): add new detection" --yes             # non-interactive
```

## Environments by branch

The environment of a change is determined by the branch it lives on, not by the content of `detection.yml`. `.dep/environments.yml` maps branches to the environments defined in `taxonomy/environments.yml`:

```yaml
schema_version: "1.0.0"
branches:
  develop: dev
  main: prod
```

- One implementation per platform: `implementations/<platform>/rule.<ext>`.
- A branch whose environment has `requires_approval: true` is protected: `dep commit` refuses to commit on it. Work on a branch (`feature/...`), open a PR into `develop` and promote with a `develop -> main` PR. It can be forced with `--allow-protected`; the first commit of a repository is exempt.
- Real protection must also be configured on the Git host.

## Validation error codes

| Code | Meaning |
|---|---|
| `DEP-SCH-001` | The `detection.yml` does not comply with the JSON Schema |
| `DEP-FIL-004` | A referenced file does not exist |
| `DEP-DUP-012` | Duplicate detection ID in the repository |
| `DEP-TAX-013` to `DEP-TAX-019` | A value is not in its taxonomy (severity, layer, data source, platform, behavior, owner team) |
| `DEP-ENV-002` | A branch maps to an environment missing from `taxonomy/environments.yml` |
| `DEP-ENV-003` | Two branches map to the same environment |
| `DEP-ENV-004` | A legacy `implementations[].environment` field is present |
| `DEP-CFG-020` | A required configuration file is missing or malformed |

`DEP-TAX-017` is retired.
