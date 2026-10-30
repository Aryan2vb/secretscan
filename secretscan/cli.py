"""Command-line interface. Exit codes: 0 = clean, 1 = secrets found, 2 = error."""

import argparse
import stat
import sys

from secretscan import __version__
from secretscan.git import GitError, hooks_dir, scan_history, scan_staged
from secretscan.report import to_json, to_text
from secretscan.scanner import scan_directory

HOOK = """#!/bin/sh
# Installed by secretscan: blocks commits that add secrets.
"{python}" -m secretscan staged || {{
  echo ""
  echo "Commit blocked by secretscan. Remove the secret, or mark a false positive with '# secretscan:ignore'."
  exit 1
}}
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="secretscan", description="Find leaked secrets in files and git history.")
    parser.add_argument("--version", action="version", version=f"secretscan {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    for name, help_text in [
        ("scan", "scan current files in a directory"),
        ("history", "scan every commit of a git repo, including deleted secrets"),
    ]:
        p = sub.add_parser(name, help=help_text)
        p.add_argument("path", nargs="?", default=".")
        p.add_argument("--json", action="store_true", help="print JSON")

    p = sub.add_parser("staged", help="scan staged changes (for a pre-commit hook)")
    p.add_argument("--json", action="store_true", help="print JSON")

    p = sub.add_parser("install-hook", help="install a git pre-commit hook in this repo")
    p.add_argument("--force", action="store_true", help="overwrite an existing pre-commit hook")
    return parser


def install_hook(force: bool) -> int:
    hook = hooks_dir() / "pre-commit"
    if hook.exists() and not force:
        print(f"{hook} already exists; use --force to overwrite it.", file=sys.stderr)
        return 2
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text(HOOK.format(python=sys.executable))
    hook.chmod(hook.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    print(f"Installed pre-commit hook at {hook}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "install-hook":
            return install_hook(args.force)
        if args.command == "scan":
            findings = scan_directory(args.path)
        elif args.command == "history":
            findings = scan_history(args.path)
        else:
            findings = scan_staged()
    except GitError as e:
        print(f"secretscan: {e}", file=sys.stderr)
        return 2
    except FileNotFoundError as e:
        print(f"secretscan: {e}", file=sys.stderr)
        return 2

    print(to_json(findings) if args.json else to_text(findings))
    return 1 if findings else 0
