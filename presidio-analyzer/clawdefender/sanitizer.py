"""Sanitize wrapper (default mode only), matching sanitize.sh behavior."""

from __future__ import annotations

from dataclasses import dataclass, field

from .detector import validate_input


@dataclass
class SanitizeResult:
    output: str
    flagged: bool
    severity: str
    patterns: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "output": self.output,
            "flagged": self.flagged,
            "severity": self.severity,
            "patterns": list(self.patterns),
        }


def sanitize(text: str) -> SanitizeResult:
    """Check text for threats and wrap with warning markers if flagged.

    Clean text is returned unchanged. Flagged text is wrapped with
    visible markers matching the bash sanitize.sh default mode output.
    """
    result = validate_input(text)

    if result.clean:
        return SanitizeResult(
            output=text,
            flagged=False,
            severity="clean",
        )

    severity = "CRITICAL" if result.score >= 90 else "WARNING"
    patterns = [f.pattern for f in result.findings[:3]]

    output = (
        "\u26a0\ufe0f [FLAGGED - Potential prompt injection detected]\n"
        f"{text}\n"
        "\u26a0\ufe0f [END FLAGGED CONTENT]"
    )

    return SanitizeResult(
        output=output,
        flagged=True,
        severity=severity,
        patterns=patterns,
    )
