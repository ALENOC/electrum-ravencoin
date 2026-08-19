#!/usr/bin/env python3
"""Create electrum/servers.signed.json using an offline Ed25519 private key.

The private key must live outside the repository.  This helper refuses a key
whose public half is not already trusted by the client, preventing accidental
publication of an unusable registry.
"""

import argparse
import base64
import datetime
import hashlib
import json
import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

# Allow execution directly from a source checkout.
ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from electrum.server_list_updater import (  # noqa: E402
    REGISTRY_SCHEMA_VERSION,
    REGISTRY_SIGNATURE_DOMAIN,
    TRUSTED_REGISTRY_KEYS,
    sanitize_signed_server_list,
)


def canonical_bytes(body: dict) -> bytes:
    return REGISTRY_SIGNATURE_DOMAIN + json.dumps(
        body,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def load_private_key(path: str) -> Ed25519PrivateKey:
    with open(path, "rb") as handle:
        key = serialization.load_pem_private_key(handle.read(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit("private key is not Ed25519")
    return key


def public_key_id(key: Ed25519PrivateKey) -> tuple[str, bytes]:
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()[:16], raw


def atomic_json_write(path: str, document: dict) -> None:
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    temporary = path + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--key",
        required=True,
        help="PEM Ed25519 private key stored outside this repository",
    )
    parser.add_argument(
        "--input",
        default=os.path.join(ROOT, "electrum", "servers.json"),
        help="server directory containing any intended operatorGroup fields",
    )
    parser.add_argument(
        "--output",
        default=os.path.join(ROOT, "electrum", "servers.signed.json"),
    )
    parser.add_argument(
        "--registry-version",
        required=True,
        type=int,
        help="strictly monotonic positive registry version",
    )
    parser.add_argument(
        "--expires-days",
        type=int,
        default=180,
        help="registry validity from generation time (default: 180 days)",
    )
    args = parser.parse_args()

    if args.registry_version < 1:
        raise SystemExit("--registry-version must be >= 1")
    if not 1 <= args.expires_days <= 730:
        raise SystemExit("--expires-days must be between 1 and 730")

    with open(args.input, "r", encoding="utf-8") as handle:
        servers = sanitize_signed_server_list(json.load(handle))

    private_key = load_private_key(args.key)
    key_id, public_raw = public_key_id(private_key)
    expected = TRUSTED_REGISTRY_KEYS.get(key_id)
    if expected is None or expected != public_raw:
        raise SystemExit(
            f"key {key_id} is not a trusted server-registry signing key in this build"
        )

    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    expires = now + datetime.timedelta(days=args.expires_days)
    body = {
        "schemaVersion": REGISTRY_SCHEMA_VERSION,
        "registryVersion": args.registry_version,
        "generatedAt": now.isoformat(),
        "expiresAt": expires.isoformat(),
        "servers": servers,
    }
    signature = private_key.sign(canonical_bytes(body))
    document = {
        "registry": body,
        "signature": {
            "algorithm": "ed25519",
            "keyId": key_id,
            "value": base64.b64encode(signature).decode("ascii"),
        },
    }
    atomic_json_write(args.output, document)
    print(
        f"signed registry v{args.registry_version} with key {key_id}; "
        f"expires {expires.isoformat()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
