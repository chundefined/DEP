"""DEP - Branch-to-environment configuration.

The environment of a change is determined by the Git branch it lives on, using
the mapping declared in `.dep/environments.yml`. This module only handles plain
data so it can be reused by commands that need to resolve environments.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

CONFIG_RELATIVE_PATH = Path(".dep") / "environments.yml"


class EnvironmentConfigError(Exception):
    """Raised when `.dep/environments.yml` is missing or malformed."""

    def __init__(self, message: str) -> None:
        self.code = "DEP-CFG-020"
        self.message = message
        super().__init__(message)


@dataclass
class EnvironmentConfig:
    """Mapping of branch names to environment identifiers."""

    branches: dict[str, str] = field(default_factory=dict)

    def environment_for(self, branch: str) -> str | None:
        return self.branches.get(branch)

    def branch_for(self, environment: str) -> str | None:
        for branch, env in self.branches.items():
            if env == environment:
                return branch
        return None


def parse_environment_config(raw: Any, source: str = ".dep/environments.yml") -> EnvironmentConfig:
    if not isinstance(raw, dict) or not isinstance(raw.get("branches"), dict):
        raise EnvironmentConfigError(f"{source} must contain a 'branches' mapping")
    branches: dict[str, str] = {}
    for branch, env in raw["branches"].items():
        if not isinstance(branch, str) or not branch.strip():
            raise EnvironmentConfigError(f"{source}: branch names must be non-empty strings")
        if not isinstance(env, str) or not env.strip():
            raise EnvironmentConfigError(
                f"{source}: branch '{branch}' must map to a non-empty environment name"
            )
        branches[branch] = env
    return EnvironmentConfig(branches=branches)


def load_environment_config(root: Path) -> EnvironmentConfig:
    """Load `<root>/.dep/environments.yml`, raising EnvironmentConfigError on problems."""
    path = Path(root) / CONFIG_RELATIVE_PATH
    if not path.is_file():
        raise EnvironmentConfigError(f"Required file missing: {path}")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise EnvironmentConfigError(f"Malformed YAML in {path}: {exc}") from exc
    return parse_environment_config(raw, str(path))


def is_protected(
    branch: str,
    config: EnvironmentConfig,
    environment_details: dict[str, dict[str, Any]],
) -> bool:
    """A branch is protected when its environment requires approval."""
    environment = config.environment_for(branch)
    if environment is None:
        return False
    details = environment_details.get(environment) or {}
    return details.get("requires_approval") is True


def load_environment_details(root: Path) -> dict[str, dict[str, Any]]:
    """Tolerantly read `taxonomy/environments.yml` entries; {} if unavailable."""
    path = Path(root) / "taxonomy" / "environments.yml"
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return {}
    envs = raw.get("environments") if isinstance(raw, dict) else None
    if not isinstance(envs, dict):
        return {}
    return {k: (v if isinstance(v, dict) else {}) for k, v in envs.items()}
