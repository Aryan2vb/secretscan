import json
import shutil
import subprocess

import pytest

from secretscan.cli import main
from secretscan.git import scan_history, scan_staged
from secretscan.report import mask
from secretscan.scanner import scan_directory
from tests import fakes

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=Test", "-c", "user.email=test@example.com",
                    "-c", "commit.gpgsign=false", *args], check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    git(tmp_path, "init", "-q", "-b", "main")
    return tmp_path


def test_directory_scan_skips_ignored_binary_and_vendor_files(tmp_path):
    (tmp_path / "app.py").write_text(f'KEY = "{fakes.aws()}"\n')
    (tmp_path / "logo.png").write_bytes(b"\x89PNG\0\0" + fakes.aws().encode())
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "lib.js").write_text(fakes.github())
    (tmp_path / "fixtures").mkdir()
    (tmp_path / "fixtures" / "keys.txt").write_text(fakes.stripe())
    (tmp_path / ".secretscanignore").write_text("# test data\nfixtures/\n")

    findings = scan_directory(tmp_path)
    assert [(f.file, f.line, f.rule) for f in findings] == [("app.py", 1, "aws-access-key")]


@needs_git
def test_history_finds_a_secret_deleted_in_a_later_commit(repo):
    key = fakes.github()
    (repo / "config.py").write_text(f'DEBUG = True\nTOKEN = "{key}"\n')
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "add config")
    (repo / "config.py").write_text("DEBUG = True\n")
    git(repo, "commit", "-qam", "remove token")

    assert scan_directory(repo) == []  # gone from the current files...

    [f] = scan_history(repo)          # ...but still in history
    assert (f.rule, f.file, f.line, f.secret) == ("github-token", "config.py", 2, key)
    assert f.author == "Test <test@example.com>"
    first_commit = subprocess.run(["git", "-C", str(repo), "rev-list", "--max-parents=0", "HEAD"],
                                  capture_output=True, text=True).stdout.strip()
    assert f.commit == first_commit


@needs_git
def test_history_reports_each_secret_once_at_its_first_commit(repo):
    key = fakes.stripe()
    for i in range(3):
        (repo / f"f{i}.js").write_text(f"const k = '{key}';\n")
        git(repo, "add", ".")
        git(repo, "commit", "-qm", f"commit {i}")
    [f] = scan_history(repo)
    assert f.file == "f0.js"


@needs_git
def test_staged_scans_only_what_is_about_to_be_committed(repo, monkeypatch):
    (repo / "old.py").write_text(f'TOKEN = "{fakes.github()}"\n')
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "old leak")  # already committed: not this commit's problem

    (repo / "new.py").write_text(f'x = 1\nKEY = "{fakes.aws()}"\n')
    git(repo, "add", "new.py")
    monkeypatch.chdir(repo)

    findings = scan_staged()
    assert [(f.file, f.line, f.rule) for f in findings] == [("new.py", 2, "aws-access-key")]


def test_cli_exit_codes_and_masked_json(tmp_path, capsys):
    assert main(["scan", str(tmp_path)]) == 0

    key = fakes.aws()
    (tmp_path / "a.txt").write_text(key)
    assert main(["scan", str(tmp_path), "--json"]) == 1
    out = capsys.readouterr().out
    assert key not in out  # never print the full secret
    [item] = json.loads(out[out.index("["):])
    assert item["secret"] == mask(key) and len(item["fingerprint"]) == 12


@needs_git
def test_pre_commit_hook_blocks_a_secret(repo, monkeypatch):
    monkeypatch.chdir(repo)
    assert main(["install-hook"]) == 0
    assert main(["install-hook"]) == 2  # won't overwrite without --force

    (repo / "leak.py").write_text(f'k = "{fakes.slack()}"\n')
    git(repo, "add", "leak.py")
    result = subprocess.run(["git", "-c", "user.name=T", "-c", "user.email=t@example.com",
                             "commit", "-m", "oops"], cwd=repo, capture_output=True, text=True)
    assert result.returncode != 0
    assert "Commit blocked by secretscan" in result.stdout + result.stderr


def test_mask():
    assert mask("ghp_abcdefghijklmnopf9") == "ghp_…f9"
    assert mask("short") == "sh…"
