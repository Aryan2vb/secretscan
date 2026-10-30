# secretscan

A command-line tool that finds leaked passwords and API keys in a git repo, including ones that were deleted in an old commit.

## Why

Deleting a secret from a file doesn't remove it from git. Every old commit still contains it, and anyone who clones the repo gets the full history. The only real fix is to **revoke the key**. secretscan finds these leaks, ideally before they're committed.

## What it finds

- **8 known key formats:** AWS access key IDs, GitHub tokens (classic and fine-grained), Slack tokens and webhooks, Stripe live keys, Google API keys, private key files
- **Generic secrets:** a value assigned to a name like `password`, `secret`, `token` or `api_key` that is at least 16 characters and random-looking (Shannon entropy ≥ 3.5 bits/char). Placeholders (`your_api_key_here`), templates (`${{ secrets.X }}`), env lookups (`os.environ[...]`) and code references are skipped.

## Install

```sh
pip install -e .
```

## Usage

```sh
secretscan scan .              # current files
secretscan history .           # every commit on every branch, including deleted secrets
secretscan staged              # only what you're about to commit
secretscan install-hook        # block commits that add secrets (git pre-commit hook)
secretscan scan . --json       # machine-readable output for CI
```

```
$ secretscan history .
.env:1  github-token  ghp_…Xq
    commit 3f9c2a71b0  Jane Dev <jane@example.com>  2026-10-30T12:01:00+05:30

Found 1 secret. Revoke them: removing a secret from code doesn't un-leak it.
```

- **Exit codes:** `0` clean, `1` secrets found (fails CI), `2` error.
- **Secrets are always masked** (first 4 + last 2 characters). JSON output adds a SHA-256 fingerprint so the same leak can be tracked without storing it.
- **History mode** reports each secret once, at the commit that first added it.
- **False positives:** list paths in `.secretscanignore` (glob patterns, like `.gitignore`), or add `# secretscan:ignore` to the line.

## Try it in two minutes

```sh
mkdir /tmp/demo && cd /tmp/demo && git init
secretscan install-hook

# A fake AWS key: the docs example with the last letter changed
echo 'AWS_KEY="AKIAIOSFODNN7EXAMPLF"' > config.py   # secretscan:ignore
git add config.py && git commit -m "add config"    # → blocked by the hook

git commit -m "add config" --no-verify             # force it in anyway
echo 'AWS_KEY = ""' > config.py && git commit -am "remove key"

secretscan scan .      # → No secrets found (the file is clean now)
secretscan history .   # → still finds it, with the commit and author that added it
```

The last two lines are the whole point: deleting a key doesn't remove it from git, so the fix is to revoke it.

## How it works

1. **Files:** walk the directory, skip `.git`, `node_modules`, binary files and files over 1 MB, and check every line against the rules.
2. **History:** run `git log -p --all --reverse --unified=0` once and scan only the added (`+`) lines of each commit, tracking file, line number, commit and author.
3. **Staged:** same, on `git diff --cached`.

## Benchmark

`python -m benchmark.run` builds a repo with **10 planted fake secrets**, 4 of them only in deleted history, and **10 decoys** that real repos contain: a UUID, a git SHA, a base64 image, a bcrypt hash, a `package-lock.json` integrity hash, a Stripe *test* key, placeholders and templates. It then scores both tools on the same repo.

| Tool | Found | Correct | False positives | Precision | Recall |
|---|---|---|---|---|---|
| secretscan | 10 | 10 | 0 | 100% | 100% |
| gitleaks 8 | 11 | 10 | 1 | 91% | 100% |

**Read this with care:**
- The benchmark is small and was written alongside the scanner, so it favours secretscan. gitleaks has far more rules and has been tested on real-world data.
- gitleaks' one "false positive" is the Stripe test key, which it flags on purpose. Whether a test key counts as a leak is a judgment call.
- Building it caught a real bug: my first fake AWS keys used digits that real key IDs never contain (they're base32: `A–Z`, `2–7`). gitleaks correctly rejected them, and secretscan's rule was tightened to match.

## Testing

```sh
pip install -e '.[dev]'
pytest
```

The tests never contain a real-looking token as a literal. Fake secrets are generated at runtime (`tests/fakes.py`), so this repo doesn't trip GitHub push protection or other scanners.
