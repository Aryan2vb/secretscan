"""Fake secrets built at runtime, so no real-looking token is ever committed to this repo."""

import random
import string

ALNUM = string.ascii_letters + string.digits
UPPER_DIGITS = string.ascii_uppercase + string.digits
BASE32 = string.ascii_uppercase + "234567"


def rand(n: int, alphabet: str = ALNUM, seed: int = 0) -> str:
    rng = random.Random(seed)
    return "".join(rng.choice(alphabet) for _ in range(n))


def aws(seed=1):
    return "AK" + "IA" + rand(16, BASE32, seed)


def github(seed=2):
    return "gh" + "p_" + rand(36, ALNUM, seed)


def github_fine_grained(seed=3):
    return "github" + "_pat_" + rand(82, ALNUM + "_", seed)


def slack(seed=4):
    return "xo" + "xb-" + rand(12, string.digits, seed) + "-" + rand(24, ALNUM, seed + 100)


def slack_webhook(seed=5):
    return ("https://hooks.slack" + ".com/services/T" + rand(10, UPPER_DIGITS, seed)
            + "/B" + rand(10, UPPER_DIGITS, seed + 1) + "/" + rand(24, ALNUM, seed + 2))


def stripe(seed=6):
    return "sk" + "_live_" + rand(32, ALNUM, seed)


def google(seed=7):
    return "AI" + "za" + rand(35, ALNUM + "_-", seed)


def private_key_header():
    return "-----BEGIN " + "RSA PRIVATE KEY-----"


def generic(seed=8, n=28):
    return rand(n, ALNUM, seed)
