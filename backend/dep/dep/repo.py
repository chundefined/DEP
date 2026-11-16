"""DEP - Repository loading for detection content repositories.

A `DetectionRepository` represents the contents of a detection content repo:
taxonomies, policies, and the set of `detection.yml` files found under
`detections/`.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from dep.environments import (
    EnvironmentConfig,
    EnvironmentConfigError,
    load_environment_config,
)
from dep.taxonomy import TaxonomySet, TaxonomyLoadError


class RepositoryLoadError(Exception):
    """Raised when the repository structure cannot be loaded."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


@dataclass
class Detection:
    """A single parsed detection.yml file."""

    id: str
    path: Path
    data: dict[str, Any]


class DetectionRepository:
    """Load and expose a detection content repository."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root).resolve()
        self.policies: dict[str, Any] = {}
        self.environments: EnvironmentConfig
        self.taxonomies: TaxonomySet
        self.detections: list[Detection] = []
        self._load()

    def _load(self) -> None:
        if not self.root.is_dir():
            raise RepositoryLoadError(
                "DEP-CFG-020",
                f"Repository path is not a directory: {self.root}",
            )

        self._load_policies()
        self._load_environments()
        self._load_taxonomies()
        self._load_detections()

    def _load_policies(self) -> None:
        policies_path = self.root / ".dep" / "policies.yml"
        if not policies_path.is_file():
            raise RepositoryLoadError(
                "DEP-CFG-020",
                f"Required file missing: {policies_path}",
            )
        try:
            self.policies = yaml.safe_load(policies_path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise RepositoryLoadError(
                "DEP-CFG-020",
                f"Malformed YAML in {policies_path}: {exc}",
            ) from exc

    def _load_environments(self) -> None:
        try:
            self.environments = load_environment_config(self.root)
        except EnvironmentConfigError as exc:
            raise RepositoryLoadError(exc.code, exc.message) from exc

    def _load_taxonomies(self) -> None:
        taxonomy_dir = self.root / "taxonomy"
        try:
            self.taxonomies = TaxonomySet(taxonomy_dir)
        except TaxonomyLoadError as exc:
            # Preserve the taxonomy error code and message.
            raise RepositoryLoadError(exc.code, exc.message) from exc

    def _load_detections(self) -> None:
        detections_dir = self.root / "detections"
        if not detections_dir.is_dir():
            raise RepositoryLoadError(
                "DEP-CFG-020",
                f"Required directory missing: {detections_dir}",
            )

        detection_files = sorted(detections_dir.rglob("detection.yml"))
        for path in detection_files:
            try:
                raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            except yaml.YAMLError as exc:
                raise RepositoryLoadError(
                    "DEP-CFG-020",
                    f"Malformed YAML in {path}: {exc}",
                ) from exc

            detection_id = raw.get("id")
            if not isinstance(detection_id, str):
                detection_id = "<missing-id>"

            self.detections.append(
                Detection(id=detection_id, path=path, data=raw)
            )
