"""Shannon entropy: how unpredictable a string is."""

import math
from collections import Counter


def shannon_entropy(s: str) -> float:
    """Return the entropy of s in bits per character.

    H = -sum(p(c) * log2(p(c))) over each distinct character c.
    "aaaa" scores 0; a random base64 string scores close to 6 (its maximum).
    """
    if not s:
        return 0.0
    n = len(s)
    return -sum((count / n) * math.log2(count / n) for count in Counter(s).values())
