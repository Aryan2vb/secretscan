"""Read git history and staged changes, and scan the lines they add."""

import re
import subprocess
from pathlib import Path

from secretscan.scanner import Finding, is_ignored, load_ignore, scan_line


class GitError(Exception):
    pass


_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
_COMMIT_MARK = "\x00"


def _git(repo: Path, *args: str) -> str:
    try:
        out = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True, check=True,
        )
    except FileNotFoundError:
        raise GitError("git is not installed")
    except subprocess.CalledProcessError as e:
        raise GitError(e.stderr.decode(errors="replace").strip() or f"git {args[0]} failed")
    return out.stdout.decode("utf-8", errors="replace")


def _scan_diff(lines, findings: list[Finding], patterns: list[str],
               commit=None, author=None, date=None) -> None:
    """Scan the added (+) lines of a unified diff with -U0."""
    path = None
    line_no = 0
    for line in lines:
        if line.startswith("+++ "):
            target = line[4:]
            path = None if target == "/dev/null" else target.removeprefix("b/")
        elif line.startswith("@@"):
            m = _HUNK.match(line)
            line_no = int(m.group(1)) if m else 0
        elif line.startswith("+") and path is not None:
            if not is_ignored(path, patterns):
                for rule_id, description, secret in scan_line(line[1:]):
                    findings.append(Finding(rule_id, description, path, line_no, secret,
                                            commit, author, date))
            line_no += 1


def scan_history(repo: str) -> list[Finding]:
    """Scan every commit on every branch, oldest first.

    Each (rule, secret) pair is reported once, at the commit that first added it,
    so a key that was later deleted still shows up.
    """
    root = Path(repo)
    patterns = load_ignore(root)
    log = _git(root, "log", "-p", "--all", "--reverse", "--no-color", "--no-ext-diff",
               "--unified=0", "--format=%x00%H%x00%an <%ae>%x00%aI")

    findings: list[Finding] = []
    commit = author = date = None
    chunk: list[str] = []

    def flush():
        _scan_diff(chunk, findings, patterns, commit, author, date)
        chunk.clear()

    for line in log.splitlines():
        if line.startswith(_COMMIT_MARK):
            flush()
            commit, author, date = line[1:].split("\x00")
        else:
            chunk.append(line)
    flush()

    unique, seen = [], set()
    for f in findings:
        key = (f.rule, f.secret)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def scan_staged(repo: str = ".") -> list[Finding]:
    """Scan only the lines added in the staged changes (what `git commit` would record)."""
    root = Path(_git(Path(repo), "rev-parse", "--show-toplevel").strip())
    diff = _git(root, "diff", "--cached", "--no-color", "--no-ext-diff", "--unified=0")
    findings: list[Finding] = []
    _scan_diff(diff.splitlines(), findings, load_ignore(root))
    return findings


def hooks_dir(repo: str = ".") -> Path:
    path = Path(_git(Path(repo), "rev-parse", "--git-path", "hooks").strip())
    return path if path.is_absolute() else Path(repo) / path
