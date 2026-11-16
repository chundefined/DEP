"""DEP - Repository validation package."""

from dep.validation.errors import ValidationError
from dep.validation.repo_validator import validate_repository

__all__ = ["ValidationError", "validate_repository"]
