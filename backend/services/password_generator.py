"""
password_generator.py
---------------------
Secure random generation using the `secrets` module.

WHY `secrets` AND NOT `random`?
    `random` is a Mersenne-Twister PRNG seeded predictably. It is designed for
    simulation and games, NOT for security. `secrets` draws from the operating
    system CSPRNG (os.urandom), which is suitable for cryptographic use.

Generated passwords are returned to the caller and NEVER stored.
"""

import secrets
import string
from typing import Dict, List

LOWERCASE = string.ascii_lowercase
UPPERCASE = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"

# Fictional, randomly combined word list for passphrase demonstrations.
# These are DEMO words only — do not reuse any generated example verbatim.
_WORD_LIST = [
    "copper", "lantern", "otter", "breeze", "marble", "falcon", "cactus",
    "harbor", "timber", "violet", "ember", "glacier", "meadow", "quartz",
    "ripple", "saddle", "thistle", "willow", "anchor", "basalt", "cedar",
    "dune", "fjord", "granite", "hollow", "ivory", "juniper", "kestrel",
    "lumen", "mosaic",
]


def generate_password(
    length: int = 20,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
) -> Dict:
    """Generate a cryptographically secure random password."""
    if length < 8:
        length = 8
    if length > 128:
        length = 128

    pools: List[str] = []
    if use_lower:
        pools.append(LOWERCASE)
    if use_upper:
        pools.append(UPPERCASE)
    if use_digits:
        pools.append(DIGITS)
    if use_symbols:
        pools.append(SYMBOLS)

    if not pools:
        pools = [LOWERCASE, UPPERCASE, DIGITS]

    all_chars = "".join(pools)

    # Guarantee at least one character from every selected pool.
    chars = [secrets.choice(pool) for pool in pools]
    while len(chars) < length:
        chars.append(secrets.choice(all_chars))

    # Fisher-Yates shuffle using secrets
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]

    return {
        "password": "".join(chars[:length]),
        "length": length,
        "character_pools": {
            "lowercase": use_lower,
            "uppercase": use_upper,
            "digits": use_digits,
            "symbols": use_symbols,
        },
        "note": "Generated locally with `secrets`. Never stored or transmitted.",
    }


def generate_passphrase(word_count: int = 5, separator: str = "-") -> Dict:
    """Generate a secure random passphrase from unrelated words."""
    if word_count < 3:
        word_count = 3
    if word_count > 10:
        word_count = 10

    words = [secrets.choice(_WORD_LIST) for _ in range(word_count)]
    # Add a random digit for extra variety (optional, still memorable)
    words.append(str(secrets.randbelow(100)))

    phrase = separator.join(words)
    return {
        "passphrase": phrase,
        "word_count": word_count,
        "note": (
            "Fictional demonstration example. Do NOT reuse this exact phrase. "
            "Generate your own and store it in a password manager."
        ),
    }