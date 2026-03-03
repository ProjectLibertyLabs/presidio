"""CLI entry point matching clawdefender.sh interface."""

from __future__ import annotations

import sys

from . import __version__
from .detector import format_human, format_json, validate_input, validate_url
from .sanitizer import sanitize

USAGE = """\
ClawDefender - Comprehensive AI Agent Protection

Usage:
  clawdefender --check-prompt [true]       Check stdin for injection
  clawdefender --check-command <cmd>       Validate shell command
  clawdefender --check-url <url>           Validate URL (SSRF)
  clawdefender --validate <input>          Full input validation
  clawdefender sanitize [text]             Sanitize text (stdin or arg)
  clawdefender --version                   Show version
  clawdefender --help                      Show this help
"""


def main(argv: list[str] | None = None) -> None:
    """Run the ClawDefender CLI."""
    args = argv if argv is not None else sys.argv[1:]

    if not args:
        print("Usage: clawdefender --help", file=sys.stderr)
        sys.exit(1)

    cmd = args[0]

    if cmd in ("--help", "-h"):
        print(USAGE)
        sys.exit(0)

    if cmd == "--version":
        print(f"ClawDefender v{__version__}")
        sys.exit(0)

    if cmd == "--check-prompt":
        text = sys.stdin.read()
        json_mode = len(args) > 1 and args[1] == "true"
        result = validate_input(text)
        print(format_json(result) if json_mode else format_human(result))
        sys.exit(0 if result.clean else 1)

    if cmd == "--check-command":
        if len(args) < 2:
            print("Usage: clawdefender --check-command <command>", file=sys.stderr)
            sys.exit(1)
        text = args[1]
        json_mode = len(args) > 2 and args[2] == "true"
        result = validate_input(text)
        print(format_json(result) if json_mode else format_human(result))
        sys.exit(0 if result.clean else 1)

    if cmd == "--check-url":
        if len(args) < 2:
            print("Usage: clawdefender --check-url <url>", file=sys.stderr)
            sys.exit(1)
        url = args[1]
        findings = validate_url(url)
        if not findings:
            print("\u2705 URL is safe")
            sys.exit(0)
        else:
            print("\U0001f534 SSRF/dangerous URL detected")
            for f in findings:
                print(f"ssrf|{f.pattern}|{f.severity}|{f.score}")
            sys.exit(1)

    if cmd == "--validate":
        if len(args) < 2:
            print("Usage: clawdefender --validate <input>", file=sys.stderr)
            sys.exit(1)
        text = args[1]
        json_mode = len(args) > 2 and args[2] == "true"
        result = validate_input(text)
        print(format_json(result) if json_mode else format_human(result))
        sys.exit(0 if result.clean else 1)

    if cmd == "sanitize":
        if len(args) > 1:
            text = args[1]
        else:
            text = sys.stdin.read()
        sr = sanitize(text)
        print(sr.output)
        sys.exit(0 if not sr.flagged else 1)

    print(f"Unknown command: {cmd}", file=sys.stderr)
    print("Usage: clawdefender --help", file=sys.stderr)
    sys.exit(1)
