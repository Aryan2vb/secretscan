import pytest

from secretscan.entropy import shannon_entropy
from secretscan.scanner import scan_line
from tests import fakes


def rules_found(line):
    return [rule for rule, _, _ in scan_line(line)]


@pytest.mark.parametrize("rule, line", [
    ("aws-access-key", f'aws_key_id = "{fakes.aws()}"'),
    ("github-token", f"GH={fakes.github()}"),
    ("github-fine-grained-pat", f"pat: {fakes.github_fine_grained()}"),
    ("slack-token", f'slack = "{fakes.slack()}"'),
    ("slack-webhook", f"curl -X POST {fakes.slack_webhook()}"),
    ("stripe-live-key", f"const stripe = require('stripe')('{fakes.stripe()}');"),
    ("google-api-key", f'<script src="https://maps.example/js?key={fakes.google()}"></script>'),
    ("private-key", fakes.private_key_header()),
])
def test_each_rule_finds_its_format(rule, line):
    assert rule in rules_found(line)


@pytest.mark.parametrize("line", [
    "The AKIA prefix marks AWS access keys.",              # prefix only
    "AK" + "IA" + "0189" * 4,                               # 0, 1, 8, 9 aren't base32
    "aws_key = AKIAIOSFODNN7EXAMPLE",                       # AWS's documented example key
    "ghp_tooshort",                                         # wrong length
    "sk" + "_test_" + fakes.rand(32),                       # Stripe *test* key
    "-----BEGIN PUBLIC KEY-----",                           # public, not private
    "x" * 200,
])
def test_known_formats_have_no_false_matches(line):
    assert rules_found(line) == []


def test_the_secret_value_is_extracted():
    token = fakes.github()
    [(rule, _, secret)] = scan_line(f'token = "{token}"')
    assert (rule, secret) == ("github-token", token)  # not also reported as generic


@pytest.mark.parametrize("line", [
    f'password = "{fakes.generic()}"',
    f"DB_PASSWORD={fakes.generic(9)}",
    f'"api_key": "{fakes.generic(10)}",',
    f"SECRET_KEY = '{fakes.generic(11, 40)}'",
    f"auth_token: {fakes.generic(12)}",
])
def test_generic_rule_finds_random_values(line):
    assert rules_found(line) == ["generic-secret"]


@pytest.mark.parametrize("line", [
    'password = "hello"',                                   # too short
    'password = "changeme_changeme_changeme"',              # placeholder
    "API_KEY=your_api_key_here_please",                     # placeholder
    'token: ${{ secrets.GITHUB_TOKEN }}',                   # template
    'password = os.environ["DB_PASSWORD"]',                 # env lookup
    "secret = settings.get_secret_from_vault()",           # code, not a value
    'author = "Jane Developer Example Name"',              # 'auth' in a normal field
    'token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa"',               # zero entropy
    f'password = "{fakes.generic()}"  # secretscan:ignore',  # inline allowlist
])
def test_generic_rule_skips_non_secrets(line):
    assert rules_found(line) == []


def test_entropy():
    assert shannon_entropy("") == 0
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("abcd") == pytest.approx(2.0)
    assert shannon_entropy(fakes.generic(n=64)) > 5
