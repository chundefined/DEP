"""DEP - Validation error representation."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ValidationError:
    """A single validation problem found in a repository."""

    code: str
    detection_id: str
    location: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}  {self.detection_id}  {self.location}  {self.message}"
