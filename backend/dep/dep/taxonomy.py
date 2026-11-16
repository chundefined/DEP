"""DEP - Taxonomy loading for detection content repositories.

A repository's `taxonomy/` directory contains controlled vocabularies that
`validate-repo` uses for semantic validation. This module loads them into a
`TaxonomySet` and exposes simple lookup helpers.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


REQUIRED_TAXONOMIES: dict[str, tuple[str, str] | None] = {
    # filename -> (root_key, attribute_name)
    "platforms.yml": ("platforms", "platforms"),
    "environments.yml": ("environments", "environments"),
    "layers.yml": ("layers", "layers"),
    "data-sources.yml": ("data_sources", "data_sources"),
    "log-sources.yml": ("log_sources", "log_sources"),
    "behaviors.yml": ("behaviors", "behaviors"),
    "owners.yml": ("owners", "owners"),
    "severity.yml": ("severity", "severity"),
    "scoring.yml": None,
}


class TaxonomyLoadError(Exception):
    """Raised when a taxonomy file cannot be loaded or is malformed."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


class TaxonomySet:
    """Container for all controlled vocabularies loaded from a repository."""

    def __init__(self, taxonomy_dir: Path) -> None:
        self.taxonomy_dir = taxonomy_dir
        self.platforms: set[str] = set()
        self.environments: set[str] = set()
        self.environment_details: dict[str, dict[str, Any]] = {}
        self.layers: set[str] = set()
        self.data_sources: set[str] = set()
        self.log_sources: dict[str, Any] = {}
        self.behaviors: set[str] = set()
        self.owners: set[str] = set()
        self.severity: set[str] = set()
        self.scoring: dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        if not self.taxonomy_dir.is_dir():
            raise TaxonomyLoadError(
                "DEP-CFG-020",
                f"Taxonomy directory not found: {self.taxonomy_dir}",
            )

        for filename, mapping in REQUIRED_TAXONOMIES.items():
            path = self.taxonomy_dir / filename
            if not path.is_file():
                raise TaxonomyLoadError(
                    "DEP-CFG-020",
                    f"Required taxonomy file missing: {path}",
                )

            try:
                raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            except yaml.YAMLError as exc:
                raise TaxonomyLoadError(
                    "DEP-CFG-020",
                    f"Malformed YAML in {path}: {exc}",
                ) from exc

            if mapping is None:
                # Required file with free structure (e.g., scoring.yml)
                attr_name = filename.replace("-", "_").replace(".yml", "")
                setattr(self, attr_name, raw)
                continue

            root_key, attr_name = mapping
            data = raw.get(root_key, {})
            if not isinstance(data, dict):
                raise TaxonomyLoadError(
                    "DEP-CFG-020",
                    f"Expected mapping under '{root_key}' in {path}",
                )
            setattr(self, attr_name, set(data.keys()))
            if attr_name == "environments":
                self.environment_details = {
                    key: (value if isinstance(value, dict) else {})
                    for key, value in data.items()
                }

        # Ignore non-required files and subdirectories such as taxonomy/attack/.

    def has_platform(self, value: str) -> bool:
        return value in self.platforms

    def has_environment(self, value: str) -> bool:
        return value in self.environments

    def has_layer(self, value: str) -> bool:
        return value in self.layers

    def has_data_source(self, value: str) -> bool:
        return value in self.data_sources

    def has_behavior(self, value: str) -> bool:
        return value in self.behaviors

    def has_owner(self, value: str) -> bool:
        return value in self.owners

    def has_severity(self, value: str) -> bool:
        return value in self.severity
