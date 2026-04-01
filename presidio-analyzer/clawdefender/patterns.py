"""All detection pattern definitions, transcribed from clawdefender.sh."""

from dataclasses import dataclass
from enum import IntEnum


class Severity(IntEnum):
    """Threat severity levels as integer scores."""

    CLEAN = 0
    INFO = 20
    WARNING = 40
    HIGH = 70
    CRITICAL = 90


@dataclass(frozen=True)
class PatternCategory:
    """A named group of regex patterns sharing a severity level."""

    name: str
    severity: Severity
    patterns: tuple[str, ...]


PROMPT_INJECTION_CRITICAL = PatternCategory(
    name="prompt_injection",
    severity=Severity.CRITICAL,
    patterns=(
        r'show.*your.*api.?key',
        r'send.*api.?key',
        r'read.*config.*key',
        r'what.*your.*api.?key',
        r'tell me.*password',
        r'show.*password',
        r'read.*[.]env',
        r'contents of.*[.]env',
        r'show.*secret',
        r'send.*credentials',
        r'what.*credentials',
        r'dump.*credential',
        r'paste.*[.]env',
        r'[.]env.*content',
        r'list.*credentials',
        r'dump.*credentials',
        r'send.*[.]env',
        r'paste.*[.]env',
        r'contents.*[.]env',
        r'show.*[.]env',
        r'what.*in.*config',
        r'ignore previous instructions',
        r'ignore all previous',
        r'ignore your instructions',
        r'disregard above',
        r'disregard.*instructions',
        r'disregard.*prompt',
        r'disregard previous',
        r'forget.*instructions',
        r'forget everything',
        r'forget your instructions',
        r'forget everything above',
        r'override your instructions',
        r'new system prompt',
        r'reset to default',
        r'new instructions',
        r'you are no longer',
        r'disable.*safety',
        r'disable.*filter',
        r'no restrictions',
        r'without.*restrictions',
        r'remove.*restrictions',
        r'without.*guidelines',
        r'no.*ethical',
        r'reveal.*system prompt',
        r'show.*system prompt',
        r'print.*system prompt',
        r'what.*instructions.*given',
        r'what.*your instructions',
        r'print.*conversation',
        r'show.*conversation history',
        r'export.*history',
        r'export all.*data',
        r'export.*user.*data',
    ),
)

PROMPT_INJECTION_WARNING = PatternCategory(
    name="prompt_injection",
    severity=Severity.WARNING,
    patterns=(
        r'you are now',
        r'your new role',
        r'pretend to be',
        r'act as if',
        r'roleplay as',
        r'hypothetically',
        r'for educational purposes',
        r'SYSTEM:',
        r'\[INST\]',
        r'<<SYS>>',
        r'jailbreak',
        r'DAN mode',
        r'pretend.*DAN',
        r"you're DAN",
        r'for academic',
        r'in a fictional',
        r'in a hypothetical',
        r'imagine a world',
        r'translate.*then execute',
        r'translate.*then run',
        r'base64.*decode',
        r'rot13',
        r'developer mode',
        r'---END',
        r'END OF SYSTEM',
        r'END OF PROMPT',
        r'<\|endoftext\|>',
        r'###.*SYSTEM',
        r'BEGIN NEW INSTRUCTIONS',
        r'STOP IGNORE',
    ),
)

COMMAND_INJECTION = PatternCategory(
    name="command_injection",
    severity=Severity.CRITICAL,
    patterns=(
        r'rm -rf /',
        r'rm -rf \*',
        r'chmod 777',
        r'mkfs\.',
        r'dd if=/dev',
        r':\(\)\{ :\|:& \};:',
        r'nc -e',
        r'ncat -e',
        r'bash -i >& /dev/tcp',
        r'/dev/tcp/',
        r'/dev/udp/',
        r'\| bash',
        r'\| sh',
        r'curl.*\| bash',
        r'wget.*\| sh',
        r'base64 -d \| bash',
        r'base64 --decode \| sh',
        r'eval.*\$\(',
        r'python -c.*exec',
    ),
)

CREDENTIAL_EXFIL = PatternCategory(
    name="credential_exfil",
    severity=Severity.CRITICAL,
    patterns=(
        r'webhook\.site',
        r'requestbin\.com',
        r'requestbin\.net',
        r'pipedream\.net',
        r'hookbin\.com',
        r'beeceptor\.com',
        r'ngrok\.io',
        r'curl.*-d.*[.]env',
        r'curl.*--data.*[.]env',
        r'cat.*[.]env.*curl',
        r'POST.*webhook.site.*API_KEY',
        r'POST.*webhook.site.*SECRET',
        r'POST.*webhook.site.*TOKEN',
    ),
)

SSRF_PATTERNS = PatternCategory(
    name="ssrf",
    severity=Severity.CRITICAL,
    patterns=(
        r'localhost',
        r'127\.0\.0\.1',
        r'0\.0\.0\.0',
        r'10\.\d+\.\d+\.\d+',
        r'172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+',
        r'192\.168\.\d+\.\d+',
        r'169\.254\.169\.254',
        r'metadata\.google',
        r'\[::1\]',
    ),
)

PATH_TRAVERSAL = PatternCategory(
    name="path_traversal",
    severity=Severity.HIGH,
    patterns=(
        r'.config/gog',
        r'cat.*[.]env',
        r'read.*[.]env',
        r'show.*[.]env',
        r'/.env',
        r'config.yaml',
        r'config.json',
        r'.ssh/id_',
        r'.gnupg',
        r'\.\./\.\./\.\.',
        r'/etc/passwd',
        r'/etc/shadow',
        r'/root/',
        r'~/.ssh/',
        r'~/.aws/',
        r'~/.gnupg/',
        r'%2e%2e%2f',
        r'\.\.%2f',
        r'%2e%2e/',
    ),
)

SENSITIVE_FILES = PatternCategory(
    name="sensitive_files",
    severity=Severity.HIGH,
    patterns=(
        r'[.]env',
        r'id_rsa',
        r'\.pem',
        r'secret',
        r'password',
        r'api.key',
        r'token',
    ),
)

ALLOWED_DOMAINS: tuple[str, ...] = (
    'github.com',
    'api.github.com',
    'api.openai.com',
    'api.anthropic.com',
    'googleapis.com',
    'google.com',
    'npmjs.org',
    'pypi.org',
    'wttr.in',
    'signalwire.com',
    'usetrmnl.com',
)

# Categories checked by validate_input (excludes SSRF, which is URL-only)
ALL_INPUT_CATEGORIES: tuple[PatternCategory, ...] = (
    PROMPT_INJECTION_CRITICAL,
    PROMPT_INJECTION_WARNING,
    COMMAND_INJECTION,
    CREDENTIAL_EXFIL,
    PATH_TRAVERSAL,
)
