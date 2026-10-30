# secretscan: Plan

**Goal:** a small Python CLI that finds secrets in files and in git history, with measured accuracy. Build it in 6 small milestones (about 1–2 weeks). Each milestone works on its own, so you can stop at any point and still have something to show.

**Stack:** Python 3.11+, standard library only (`re`, `math`, `subprocess`, `argparse`, `json`), `pytest` for tests.

## Layout

```
secretscan/
  rules.py      # the patterns: name, regex, example
  entropy.py    # Shannon entropy
  scanner.py    # scan text → findings
  git.py        # read history and staged changes
  report.py     # text + JSON output, masking
  cli.py        # argparse commands: scan, history, staged
tests/
testdata/
  make_test_repo.sh   # builds a repo with planted FAKE secrets
```

A finding is one small record:

```python
@dataclass
class Finding:
    rule: str        # "github-token"
    file: str
    line: int
    secret: str      # never printed in full
    commit: str | None = None
    author: str | None = None
```

---

## Milestone 1: Scan files with regex rules

- [ ] Walk a directory; skip `.git/`, binary files (contains a `\0` byte) and files over 1 MB
- [ ] Check every line against each rule
- [ ] Print `file:line  rule  masked-secret`, for example `config.py:12  github-token  ghp_ab…f9`
- [ ] Tests: one positive and one negative example per rule

Starting rules (all public formats):

| Rule | Pattern |
|---|---|
| AWS access key | `AKIA[0-9A-Z]{16}` |
| GitHub token | `gh[pousr]_[A-Za-z0-9]{36}`, `github_pat_[A-Za-z0-9_]{82}` |
| Slack token | `xox[baprs]-[A-Za-z0-9-]{10,}` |
| Stripe live key | `sk_live_[A-Za-z0-9]{24,}` |
| Google API key | `AIza[0-9A-Za-z_-]{35}` |
| Private key file | `-----BEGIN (RSA \|EC \|OPENSSH \|DSA )?PRIVATE KEY-----` |

**You can explain:** why these formats are easy to detect (fixed prefixes), and why vendors added prefixes like `ghp_` (to make leaks detectable).

## Milestone 2: Entropy for generic secrets

- [ ] `shannon_entropy(s)` = −Σ p(c)·log₂ p(c) over the characters in `s`
- [ ] New rule: a value assigned to a suspicious name (`password|secret|token|api_key|apikey|auth`), where the value is ≥ 20 characters and entropy > 4.0
- [ ] Ignore obvious placeholders: `changeme`, `xxxx`, `<your-key>`, `${VAR}`, `os.environ[...]`
- [ ] Tests: a random string passes the check; `password = "hello"` and `token = "${TOKEN}"` don't

**You can explain:** what entropy measures (how unpredictable a string is), why it catches random keys and misses "password123", and the false-positive trade-off.

## Milestone 3: Scan git history

- [ ] Run `git log -p --all --no-color --format=...` (one `subprocess` call)
- [ ] Parse commits: hash, author, and for each file only the **added** lines (starting with `+`)
- [ ] Run the same scanner on those lines; findings include commit + author
- [ ] Deduplicate: the same secret in 10 commits → one finding showing the first commit it appeared in
- [ ] Test: make a repo, commit a fake key, delete it in the next commit → `scan` finds nothing, `history` finds it

**You can explain:** git stores snapshots, so "deleted" data stays in history, and why the real fix is to **revoke the key**. Rewriting history doesn't help once someone has cloned the repo.

## Milestone 4: Make it usable in CI

- [ ] Exit code `1` when anything is found, `0` when clean
- [ ] `--json` output
- [ ] `.secretscanignore`: paths to skip (like `.gitignore`), plus an inline `# secretscan:ignore` comment for a known false positive
- [ ] Mask secrets everywhere: first 4 and last 2 characters only

**You can explain:** why a scanner must never print the full secret (CI logs are often widely readable).

## Milestone 5: Pre-commit hook

- [ ] `secretscan staged`: scan `git diff --cached` (added lines only)
- [ ] `secretscan install-hook`: writes `.git/hooks/pre-commit` that runs it
- [ ] Demo: try to commit a fake key → the commit is blocked with a clear message

**You can explain:** catching a secret before the commit is far cheaper than cleaning up after a push.

## Milestone 6: Measure it (this is what makes it "research")

- [ ] `testdata/make_test_repo.sh` builds a repo with:
  - **10 planted fake secrets**: some in current files, some only in deleted history, in different file types
  - **10 decoys** that should *not* be flagged: UUIDs, git SHAs, base64 images, placeholder values, test fixtures
- [ ] Run secretscan and compute **precision** (how many flagged items were real) and **recall** (how many real secrets were found)
- [ ] Run [gitleaks](https://github.com/gitleaks/gitleaks) on the same repo and compare honestly
- [ ] Write up the results in the README: a table, what you miss, and why

---

## Safety rules

- Use only fake secrets. AWS's documented example key `AKIAIOSFODNN7EXAMPLE` is safe; for other formats generate random strings with the right prefix.
- Never test against other people's repos without permission, and never try to use a key you find. If you find a real leaked key in a public repo, report it privately to the owner.

## Interview questions to prepare for

1. Why doesn't deleting the file fix a leaked secret? What does?
2. What is entropy, and why is it a noisy signal?
3. How would you lower false positives without missing real keys?
4. Your tool found a key in a public repo. What do you do?
5. How would you scan a repo with 100,000 commits quickly?
6. How do GitHub push protection and secret scanning work, at a high level?
