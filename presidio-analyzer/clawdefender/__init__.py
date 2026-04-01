"""ClawDefender - Comprehensive AI agent security scanning and validation."""

__version__ = "1.0.0"

from .detector import (
    Finding,
    ScanResult,
    is_allowed_domain,
    validate_input,
    validate_url,
)
from .sanitizer import SanitizeResult, sanitize

__all__ = [
    "validate_input",
    "validate_url",
    "is_allowed_domain",
    "sanitize",
    "ScanResult",
    "SanitizeResult",
    "Finding",
]
