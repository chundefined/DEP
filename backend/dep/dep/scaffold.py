"""DEP - Scaffolding of new detections (``dep new-detection``)."""

from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass
from datetime import date
from importlib import resources
from pathlib import Path
from string import Template

import yaml

import dep.schemas
import dep.templates.detection as detection_template

DEFAULT_PLATFORM = "sentinel"
MIN_NAME_LENGTH = 3

_ID_RE = re.compile(r"^DET-(\d+)")
_EXTENSIONS = {"kql": "kql", "aql": "aql", "spl": "spl", "lucene": "lucene", "fql": "fql"}
_COMMENTS = {"kql": "//", "aql": "--"}


class ScaffoldError(Exception):
    """Raised for user-facing scaffolding errors (invalid name, platform, target)."""


@dataclass(frozen=True)
class Platform:
    id: str
    language: str

    @property
    def extension(self) -> str:
        return _EXTENSIONS.get(self.language, self.language)

    @property
    def comment(self) -> str:
        return _COMMENTS.get(self.language, "#")

    @property
    def suffix(self) -> str:
        return self.id.upper().replace("_", "-")


def slugify(name: str) -> str:
    """Lowercase, replace whitespace runs by ``-`` and drop unsafe characters."""
    slug = re.sub(r"\s+", "-", name.strip().lower())
    slug = re.sub(r"[^a-z0-9-]", "", slug)
    slug = re.sub(r"-+", "-", slug).strip("-")
    if not slug:
        raise ScaffoldError(f"Name '{name}' does not contain letters or digits.")
    return slug


def next_detection_id(detections_dir: Path) -> str:
    """Return the next free ``DET-NNNN`` id (highest existing number plus one)."""
    highest = 0
    detections_dir = Path(detections_dir)
    if detections_dir.is_dir():
        for path in detections_dir.rglob("*"):
            match = _ID_RE.match(path.name)
            if match and path.is_dir():
                highest = max(highest, int(match.group(1)))
        for path in detections_dir.rglob("detection.yml"):
            try:
                data = yaml.safe_load(path.read_text(encoding="utf-8"))
            except (yaml.YAMLError, OSError):
                continue
            value = data.get("id") if isinstance(data, dict) else None
            match = _ID_RE.match(value) if isinstance(value, str) else None
            if match:
                highest = max(highest, int(match.group(1)))
    return f"DET-{highest + 1:04d}"


def _schema_languages() -> set[str]:
    schema_path = resources.files(dep.schemas) / "detection.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    return set(schema["$defs"]["implementation"]["properties"]["logic"]["properties"]["language"]["enum"])


def resolve_platforms(root: Path, requested: list[str] | None) -> list[Platform]:
    """Validate requested platforms against the repository taxonomy."""
    path = Path(root) / "taxonomy" / "platforms.yml"
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ScaffoldError(f"Cannot read {path}: {exc}") from exc
    available = raw.get("platforms") or {}
    allowed_languages = _schema_languages()

    result: list[Platform] = []
    for platform_id in dict.fromkeys(requested or [DEFAULT_PLATFORM]):
        entry = available.get(platform_id)
        if entry is None:
            listed = ", ".join(sorted(available)) or "(none)"
            raise ScaffoldError(
                f"Unknown platform '{platform_id}'. Available platforms: {listed}"
            )
        language = (entry or {}).get("language")
        if language not in allowed_languages:
            raise ScaffoldError(
                f"Platform '{platform_id}' has language '{language}', which is not accepted "
                f"by the detection schema ({', '.join(sorted(allowed_languages))})."
            )
        result.append(Platform(id=platform_id, language=language))
    return result


def _template(name: str) -> str:
    return (resources.files(detection_template) / name).read_text(encoding="utf-8")


def render_detection(det_id: str, name: str, platforms: list[Platform]) -> str:
    """Render ``detection.yml`` from the bundled template."""
    number = det_id.split("-", 1)[1]
    implementations, log_sources = [], []
    for platform in platforms:
        values = {
            "num": number,
            "suffix": platform.suffix,
            "platform": platform.id,
            "language": platform.language,
            "ext": platform.extension,
        }
        implementations.append(Template(_template("implementation.yml")).substitute(values).rstrip("\n"))
        log_sources.append(Template(_template("log_source.yml")).substitute(values).rstrip("\n"))
    return Template(_template("detection.yml")).substitute(
        id=det_id,
        name=json.dumps(name, ensure_ascii=False),
        implementations="\n".join(implementations),
        log_sources="\n".join(log_sources),
    )


def create_detection(root: Path, name: str, platforms: list[Platform]) -> Path:
    """Create a new detection folder under ``root/detections`` and return its path."""
    name = name.strip()
    if len(name) < MIN_NAME_LENGTH:
        raise ScaffoldError(f"Name must have at least {MIN_NAME_LENGTH} characters.")
    slug = slugify(name)
    det_id = next_detection_id(Path(root) / "detections")
    target = Path(root) / "detections" / f"{det_id}-{slug}"
    if target.exists():
        raise ScaffoldError(f"Target already exists: {target}")

    files: dict[Path, str] = {
        target / "detection.yml": render_detection(det_id, name, platforms),
        target / "documentation" / "overview.md": Template(_template("overview.md")).substitute(
            id=det_id,
            name=name,
            platforms=", ".join(f"{p.id} ({p.language})" for p in platforms),
        ),
    }
    for platform in platforms:
        files[target / "implementations" / platform.id / f"rule.{platform.extension}"] = Template(
            _template("rule.txt")
        ).substitute(
            comment=platform.comment, language=platform.language, id=det_id, platform=platform.id
        )

    try:
        for path, content in files.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
    except OSError as exc:
        shutil.rmtree(target, ignore_errors=True)
        raise ScaffoldError(f"Could not create {target}: {exc}") from exc
    return target
