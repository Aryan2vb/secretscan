"""Scan text and directories for secrets."""

import fnmatch
import os
from dataclasses import dataclass
from pathlib import Path

from secretscan.rules import GENERIC_DESCRIPTION, GENERIC_ID, KNOWN_EXAMPLES, RULES, generic_matches

IGNORE_FILE = ".secretscanignore"
INLINE_IGNORE = "secretscan:ignore"
MAX_FILE_SIZE = 1_000_000
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache"}


@dataclass
class Finding:
    rule: str
    description: str
    file: str
    line: int
    secret: str
    commit: str | None = None
    author: str | None = None
    date: str | None = None


def scan_line(text: str) -> list[tuple[str, str, str]]:
    """Return (rule id, description, secret) for every secret on one line."""
    if INLINE_IGNORE in text:
        return []
    hits = []
    seen = set()
    for rule in RULES:
        for m in rule.pattern.finditer(text):
            secret = m.group(rule.group)
            if secret in KNOWN_EXAMPLES:
                continue
            if secret not in seen:
                seen.add(secret)
                hits.append((rule.id, rule.description, secret))
    for value in generic_matches(text):
        # Skip if a specific rule already reported this value (or part of it).
        if not any(value in s or s in value for s in seen):
            seen.add(value)
            hits.append((GENERIC_ID, GENERIC_DESCRIPTION, value))
    return hits


def scan_text(text: str, path: str) -> list[Finding]:
    findings = []
    for number, line in enumerate(text.splitlines(), start=1):
        for rule_id, description, secret in scan_line(line):
            findings.append(Finding(rule_id, description, path, number, secret))
    return findings


def load_ignore(root: Path) -> list[str]:
    """Read glob patterns from .secretscanignore (one per line, # for comments)."""
    path = root / IGNORE_FILE
    if not path.is_file():
        return []
    patterns = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            patterns.append(line.rstrip("/"))
    return patterns


def is_ignored(relpath: str, patterns: list[str]) -> bool:
    """True if relpath, or any directory above it, matches an ignore pattern."""
    parts = relpath.split("/")
    candidates = ["/".join(parts[: i + 1]) for i in range(len(parts))] + parts
    return any(fnmatch.fnmatch(c, p) for c in candidates for p in patterns)


def is_binary(data: bytes) -> bool:
    return b"\0" in data[:8192]


def scan_directory(root: str | os.PathLike) -> list[Finding]:
    """Scan every text file under root, skipping ignored, binary and huge files."""
    root = Path(root)
    patterns = load_ignore(root)
    findings = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            path = Path(dirpath) / name
            rel = path.relative_to(root).as_posix()
            if name == IGNORE_FILE or is_ignored(rel, patterns):
                continue
            try:
                if path.stat().st_size > MAX_FILE_SIZE:
                    continue
                data = path.read_bytes()
            except OSError:
                continue
            if is_binary(data):
                continue
            findings.extend(scan_text(data.decode("utf-8", errors="replace"), rel))
    return findings
