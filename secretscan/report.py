"""Print findings as text or JSON, never showing a secret in full."""

import hashlib
import json
from dataclasses import asdict

from secretscan.scanner import Finding


def mask(secret: str) -> str:
    """Keep the first 4 and last 2 characters: 'ghp_ab…f9'."""
    if len(secret) <= 8:
        return secret[:2] + "…"
    return f"{secret[:4]}…{secret[-2:]}"


def fingerprint(secret: str) -> str:
    """A stable ID for a secret, so the same leak can be tracked without storing it."""
    return hashlib.sha256(secret.encode()).hexdigest()[:12]


def to_text(findings: list[Finding]) -> str:
    if not findings:
        return "No secrets found."
    lines = []
    for f in findings:
        lines.append(f"{f.file}:{f.line}  {f.rule}  {mask(f.secret)}")
        if f.commit:
            lines.append(f"    commit {f.commit[:10]}  {f.author}  {f.date}")
    noun = "secret" if len(findings) == 1 else "secrets"
    lines.append(f"\nFound {len(findings)} {noun}. Revoke them: removing a secret from code doesn't un-leak it.")
    return "\n".join(lines)


def to_json(findings: list[Finding]) -> str:
    out = []
    for f in findings:
        item = asdict(f)
        item["secret"] = mask(f.secret)
        item["fingerprint"] = fingerprint(f.secret)
        out.append(item)
    return json.dumps(out, indent=2)
