"""Benchmark: build a repo with 10 planted fake secrets and 10 decoys, then measure
precision and recall for secretscan (and gitleaks, if it's installed).

    python -m benchmark.run

Some secrets live only in deleted history. Decoys are things real repos contain that
look secret-ish but aren't: hashes, UUIDs, placeholders, test keys.
"""

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from secretscan.git import scan_history
from tests import fakes

ROOT = Path(__file__).resolve().parent.parent
WORK = ROOT / "testdata" / "work" / "bench"


def git(*args):
    subprocess.run(["git", "-C", str(WORK), "-c", "user.name=Bench", "-c", "user.email=bench@example.com",
                    "-c", "commit.gpgsign=false", *args], check=True, capture_output=True)


def commit(files: dict[str, str], message: str):
    for path, content in files.items():
        p = WORK / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    git("add", "-A")
    git("commit", "-qm", message)


def build() -> list[dict]:
    """Create the benchmark repo; return the planted secrets."""
    shutil.rmtree(WORK, ignore_errors=True)
    WORK.mkdir(parents=True)
    git("init", "-q", "-b", "main")

    s = {
        "aws": fakes.aws(101), "github": fakes.github(102), "slack": fakes.slack(103),
        "stripe": fakes.stripe(104), "google": fakes.google(105), "webhook": fakes.slack_webhook(106),
        "db_password": fakes.generic(107, 24), "api_key": fakes.generic(108, 32),
        "django": fakes.generic(109, 50), "private_key": fakes.private_key_header(),
    }
    planted = [
        {"name": "aws", "where": "current", "file": "app/config.py"},
        {"name": "github", "where": "deleted", "file": ".env"},
        {"name": "slack", "where": "current", "file": "deploy/settings.yaml"},
        {"name": "stripe", "where": "deleted", "file": "web/payments.js"},
        {"name": "google", "where": "current", "file": "web/index.html"},
        {"name": "private_key", "where": "deleted", "file": "deploy/id_rsa"},
        {"name": "db_password", "where": "current", "file": "docker-compose.yml"},
        {"name": "api_key", "where": "deleted", "file": "config.json"},
        {"name": "webhook", "where": "current", "file": "scripts/notify.sh"},
        {"name": "django", "where": "current", "file": "app/settings.py"},
    ]
    for p in planted:
        p["secret"] = s[p["name"]]

    hex40 = fakes.rand(40, "0123456789abcdef", 200)
    decoys = {
        "app/models.py": 'request_id = "550e8400-e29b-41d4-a716-446655440000"\n'
                         f'last_commit = "{hex40}"\n',
        "web/style.css": ".logo { background: url(data:image/png;base64,"
                         + fakes.rand(120, fakes.ALNUM + "+/", 201) + "); }\n",
        ".env.example": "API_KEY=your_api_key_here\nDATABASE_URL=postgres://localhost/app\n",
        "app/db.py": 'password = os.environ["DB_PASSWORD"]\n',
        ".github/workflows/ci.yml": "env:\n  token: ${{ secrets.GITHUB_TOKEN }}\n",
        "docs/aws.md": "Access key IDs start with AKIA followed by 16 uppercase characters.\n",
        "app/fixtures.py": 'password_hash = "$2b$12$' + fakes.rand(53, fakes.ALNUM + "./", 202) + '"\n',
        "package-lock.json": '{"integrity": "sha512-' + fakes.rand(86, fakes.ALNUM + "+/", 203) + '=="}\n',
        "tests/test_billing.py": 'STRIPE_KEY = "sk' + '_test_' + fakes.rand(32, fakes.ALNUM, 204) + '"\n',
        "app/version.py": 'build_token_count = 12\nVERSION_TAG = "v2.14.0-rc.1+build.20260301"\n',
    }

    commit({"README.md": "# demo app\n", **decoys}, "initial app")
    commit({
        "app/config.py": f'AWS_ACCESS_KEY_ID = "{s["aws"]}"\nREGION = "ap-south-1"\n',
        ".env": f"GITHUB_TOKEN={s['github']}\n",
        "deploy/settings.yaml": f"slack:\n  bot_token: {s['slack']}\n",
        "web/payments.js": f"const stripe = require('stripe')('{s['stripe']}');\n",
        "web/index.html": f'<script src="https://maps.googleapis.com/maps/api/js?key={s["google"]}"></script>\n',
        "deploy/id_rsa": s["private_key"] + "\n" + fakes.rand(64, fakes.ALNUM, 205) + "\n-----END RSA PRIVATE KEY-----\n",
        "docker-compose.yml": f"services:\n  db:\n    environment:\n      DB_PASSWORD: {s['db_password']}\n",
        "config.json": f'{{"api_key": "{s["api_key"]}"}}\n',
        "scripts/notify.sh": f"curl -X POST -d 'deployed' {s['webhook']}\n",
        "app/settings.py": f"SECRET_KEY = '{s['django']}'\n",
    }, "add config")
    for p in planted:
        if p["where"] == "deleted":
            (WORK / p["file"]).unlink()
    git("add", "-A")
    git("commit", "-qm", "remove secrets")
    return planted


def score(found: list[str], planted: list[dict]) -> dict:
    """A finding is correct if it matches (or overlaps) a planted secret."""
    def matches(f, p):
        return f in p["secret"] or p["secret"] in f

    tp = [f for f in found if any(matches(f, p) for p in planted)]
    fp = [f for f in found if f not in tp]
    hit = [p for p in planted if any(matches(f, p) for f in found)]
    missed = [p for p in planted if p not in hit]
    return {
        "findings": len(found),
        "true_positives": len(tp),
        "false_positives": len(fp),
        "precision": len(tp) / len(found) if found else 0.0,
        "recall": len(hit) / len(planted),
        "missed": [f'{p["name"]} ({p["where"]}, {p["file"]})' for p in missed],
        "false_positive_values": [f[:12] + "…" for f in fp],
    }


def run_gitleaks() -> list[str] | None:
    exe = shutil.which("gitleaks")
    if not exe:
        return None
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "report.json"
        subprocess.run([exe, "git", str(WORK), "--report-format", "json", "--report-path", str(report),
                        "--no-banner", "--exit-code", "0"], capture_output=True)
        if not report.exists():
            return None
        return [r["Secret"] for r in json.loads(report.read_text() or "[]")]


def main() -> int:
    planted = build()
    results = {"secretscan": score([f.secret for f in scan_history(WORK)], planted)}
    gl = run_gitleaks()
    if gl is not None:
        results["gitleaks"] = score(gl, planted)

    print(f"Benchmark repo: {WORK}  ({len(planted)} planted secrets, 10 decoys, "
          f"{sum(p['where'] == 'deleted' for p in planted)} only in deleted history)\n")
    print(f"{'tool':<12}{'found':>7}{'TP':>5}{'FP':>5}{'precision':>11}{'recall':>8}")
    for tool, r in results.items():
        print(f"{tool:<12}{r['findings']:>7}{r['true_positives']:>5}{r['false_positives']:>5}"
              f"{r['precision']:>10.0%}{r['recall']:>9.0%}")
    for tool, r in results.items():
        if r["missed"] or r["false_positive_values"]:
            print(f"\n{tool}:")
            for m in r["missed"]:
                print(f"  missed: {m}")
            for v in r["false_positive_values"]:
                print(f"  false positive: {v}")
    if gl is None:
        print("\n(gitleaks not installed; install it to compare)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
