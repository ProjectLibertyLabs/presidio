"""Core detection engine matching clawdefender.sh behavior."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from .patterns import (
    ALL_INPUT_CATEGORIES,
    ALLOWED_DOMAINS,
    SSRF_PATTERNS,
    PatternCategory,
    Severity,
)


@dataclass
class Finding:
    """A single pattern match finding."""

    module: str
    pattern: str
    match: str
    severity: str
    score: int

    def to_dict(self) -> dict:
        """Return the finding as a dictionary."""
        return {
            "module": self.module,
            "pattern": self.pattern,
            "match": self.match,
            "severity": self.severity,
            "score": self.score,
        }


@dataclass
class ScanResult:
    """Aggregated result of scanning text against all categories."""

    clean: bool
    severity: str
    score: int
    action: str
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Return the scan result as a dictionary."""
        return {
            "clean": self.clean,
            "severity": self.severity,
            "score": self.score,
            "action": self.action,
            "findings": [f.to_dict() for f in self.findings],
        }


def check_pattern(text: str, pattern: str) -> str | None:
    """Check a single pattern against text. Returns the matched string or None."""
    m = re.search(pattern, text, re.IGNORECASE)
    return m.group(0) if m else None


def check_category(text: str, category: PatternCategory) -> list[Finding]:
    """Check all patterns in a category against text."""
    findings: list[Finding] = []
    severity_name = category.severity.name.lower()
    for pattern in category.patterns:
        match = check_pattern(text, pattern)
        if match is not None:
            findings.append(Finding(
                module=category.name,
                pattern=pattern,
                match=match,
                severity=severity_name,
                score=int(category.severity),
            ))
    return findings


def is_allowed_domain(url: str) -> bool:
    """Check if a URL belongs to an allowed domain."""
    url_lower = url.lower()
    return any(domain in url_lower for domain in ALLOWED_DOMAINS)


def validate_url(url: str) -> list[Finding]:
    """Validate a URL for SSRF patterns."""
    if is_allowed_domain(url):
        return []
    return check_category(url, SSRF_PATTERNS)


def validate_input(text: str) -> ScanResult:
    """Run all input validation categories and return a ScanResult."""
    all_findings: list[Finding] = []
    for category in ALL_INPUT_CATEGORIES:
        all_findings.extend(check_category(text, category))

    max_score = max((f.score for f in all_findings), default=0)

    if max_score >= Severity.CRITICAL:
        action, severity = "block", "critical"
    elif max_score >= Severity.HIGH:
        action, severity = "block", "high"
    elif max_score >= Severity.WARNING:
        action, severity = "warn", "warning"
    else:
        action, severity = "allow", "clean"

    return ScanResult(
        clean=(action == "allow"),
        severity=severity,
        score=max_score,
        action=action,
        findings=all_findings,
    )


def format_json(result: ScanResult) -> str:
    """Format a ScanResult as JSON matching bash output."""
    d = result.to_dict()
    del d["findings"]
    return json.dumps(d, indent=2)


def format_human(result: ScanResult) -> str:
    """Format a ScanResult as human-readable text matching bash output."""
    if result.action == "allow":
        return "\u2705 Clean - No threats detected"

    lines = ["\n=== Security Scan Results ==="]
    severity_icons = {
        "critical": "\U0001f534 CRITICAL",
        "high": "\U0001f7e0 HIGH",
        "warning": "\U0001f7e1 WARNING",
        "info": "\u2139\ufe0f  INFO",
    }
    for f in result.findings:
        icon = severity_icons.get(f.severity, f.severity.upper())
        lines.append(f"{icon} [{f.module}]: Pattern: {f.pattern} (score: {f.score})")
    lines.append("")
    lines.append(f"Max Score: {result.score}")
    lines.append(f"Action: {result.action}")
    return "\n".join(lines)
