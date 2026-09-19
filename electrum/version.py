import re
from typing import Tuple

ELECTRUM_VERSION = "1.3.0rc3"  # version of the client package
APK_VERSION = "4.4.6.0"  # read by buildozer.spec

PROTOCOL_VERSION = "1.11"  # protocol version requested

# The hash of the mnemonic seed must begin with this
SEED_PREFIX = "01"  # Standard wallet
SEED_PREFIX_SW = "100"  # Segwit wallet
SEED_PREFIX_2FA = "101"  # Two-factor authentication
SEED_PREFIX_2FA_SW = "102"  # Two-factor auth, using segwit


def seed_prefix(seed_type):
    if seed_type == "standard":
        return SEED_PREFIX
    elif seed_type == "segwit":
        return SEED_PREFIX_SW
    elif seed_type == "2fa":
        return SEED_PREFIX_2FA
    elif seed_type == "2fa_segwit":
        return SEED_PREFIX_2FA_SW
    raise Exception(f"unknown seed_type: {seed_type}")


_VERSION_RE = re.compile(r"\s*(\d+(?:\.\d+)*)(?:(a|b|rc)(\d+))?\s*\Z")

# a final release sorts above every pre-release carrying the same number
_STAGE_ORDER = {"a": 0, "b": 1, "rc": 2, None: 3}


def parse_version(vstring: str) -> Tuple[Tuple[int, ...], int, int]:
    """Return a comparable key for a version string such as "1.3.0", "1.3.0rc3"
    or "4.4.6.0".

    StrictVersion, previously used by the update checker, accepts only the "a"
    and "b" pre-release tags and at most three numeric components, so it
    rejected the "rc" suffix used by this client:

        ValueError: invalid version number '1.3.0rc3'
    """
    match = _VERSION_RE.match(vstring)
    if not match:
        raise ValueError(f"invalid version number '{vstring}'")
    numbers, stage, stage_number = match.groups()
    release = tuple(int(n) for n in numbers.split("."))
    # pad so that "1.3" and "1.3.0.0" compare equal
    if len(release) < 4:
        release = release + (0,) * (4 - len(release))
    return release, _STAGE_ORDER[stage], int(stage_number or 0)
