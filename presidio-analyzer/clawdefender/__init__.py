"""ClawDefender - Comprehensive AI agent security scanning and validation."""

__version__ = "1.0.0"

from .detector import validate_input, validate_url, is_allowed_domain, ScanResult, Finding
from .sanitizer import sanitize, SanitizeResult

__all__ = [
    "validate_input",
    "validate_url",
    "is_allowed_domain",
    "sanitize",
    "ScanResult",
    "SanitizeResult",
    "Finding",
]
