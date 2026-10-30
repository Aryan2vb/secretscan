"""Detection rules: known key formats, plus a generic entropy-based rule."""

import re
from dataclasses import dataclass

from secretscan.entropy import shannon_entropy


@dataclass(frozen=True)
class Rule:
    id: str
    description: str
    pattern: re.Pattern
    group: int = 0  # which regex group holds the secret


# Characters that can't continue a token; used instead of \b, which fails next to "-".
_END = r"(?![A-Za-z0-9_-])"

RULES = [
    Rule("aws-access-key", "AWS access key ID",
         re.compile(r"(?<![A-Z0-9])((?:AKIA|ASIA)[A-Z2-7]{16})(?![A-Z0-9])"), 1),  # key IDs are base32
    Rule("github-token", "GitHub token",
         re.compile(r"(?<![A-Za-z0-9_])(gh[pousr]_[A-Za-z0-9]{36})" + _END), 1),
    Rule("github-fine-grained-pat", "GitHub fine-grained personal access token",
         re.compile(r"(?<![A-Za-z0-9_])(github_pat_[A-Za-z0-9_]{82})" + _END), 1),
    Rule("slack-token", "Slack token",
         re.compile(r"(?<![A-Za-z0-9])(xox[baprs]-[A-Za-z0-9-]{10,})" + _END), 1),
    Rule("slack-webhook", "Slack incoming webhook URL",
         re.compile(r"(https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]{16,})"), 1),
    Rule("stripe-live-key", "Stripe live secret key",
         re.compile(r"(?<![A-Za-z0-9])((?:sk|rk)_live_[A-Za-z0-9]{24,})" + _END), 1),
    Rule("google-api-key", "Google API key",
         re.compile(r"(?<![A-Za-z0-9])(AIza[0-9A-Za-z_-]{35})" + _END), 1),
    Rule("private-key", "Private key",
         re.compile(r"(-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)"), 1),
]


# Public example values from vendor documentation; never real keys.
KNOWN_EXAMPLES = {
    "AKIAIOSFODNN7EXAMPLE",  # AWS docs
}


# --- Generic rule: a random-looking value assigned to a secret-sounding name ---

GENERIC_ID = "generic-secret"
GENERIC_DESCRIPTION = "High-entropy value assigned to a secret-like name"

MIN_LENGTH = 16
MIN_ENTROPY = 3.5

_ASSIGNMENT = re.compile(
    r"""(?ix)
    (?P<name>[\w.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|credential|auth)[\w.-]*)
    ["']?\s*(?::=|=>|=|:)\s*
    (?P<quote>["'`]?)
    (?P<value>[^\s"'`,;]+)
    """
)

# Values that are clearly not real secrets.
_PLACEHOLDER_WORDS = (
    "example", "sample", "dummy", "placeholder", "changeme", "change_me", "your_",
    "your-", "redacted", "xxxx", "****", "todo", "fake", "test_", "<", ">",
)
_TEMPLATE = re.compile(r"\$\{|\{\{|%\(|\$[A-Z_]+|os\.environ|process\.env|getenv|secrets\.")
_CODE_REFERENCE = re.compile(r"[A-Za-z_]\w*(\.[A-Za-z_]\w*)+(\(.*)?|[A-Za-z_]\w*\(.*")


def looks_like_placeholder(value: str) -> bool:
    lower = value.lower()
    if any(word in lower for word in _PLACEHOLDER_WORDS):
        return True
    if _TEMPLATE.search(value):
        return True
    return len(set(value)) <= 3  # "aaaaaaaa", "12121212"


def generic_matches(line: str) -> list[str]:
    """Return values that look like secrets assigned to secret-like names."""
    found = []
    for m in _ASSIGNMENT.finditer(line):
        value = m.group("value")
        if len(value) < MIN_LENGTH or looks_like_placeholder(value):
            continue
        # Unquoted values like `config.get_password()` are code, not secrets.
        if not m.group("quote") and _CODE_REFERENCE.fullmatch(value):
            continue
        if shannon_entropy(value) < MIN_ENTROPY:
            continue
        found.append(value)
    return found
