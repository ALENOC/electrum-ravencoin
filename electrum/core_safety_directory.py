# Copyright (c) 2026, ALENOC
#
# The MIT License (MIT).  See LICENCE for details.

"""Consume the signed server directory as a discovery hint.

The directory answers "where might there be servers", never "which servers are
safe".  Its signature protects it from being forged or replayed on the way here;
it says nothing about whether the endpoint at the other end is honest right now.

Every candidate this module returns still has to go through the full connection
path: ``server.version``, ``server.ravencoin_backend``, the certified-release
policy, and independent chain validation.  A directory entry marked SAFE that
fails any of those is rejected, which is the whole point of not treating a
directory as an authority.
"""

import base64
import datetime
import json
from typing import Dict, List, Mapping, Optional

DIRECTORY_SCHEMA_VERSION = 1

#: Public keys allowed to sign a server directory.  Deliberately a *different*
#: key from the Core safety policy: the directory is lower-stakes discovery
#: data, and one compromised key should not grant both roles.
TRUSTED_DIRECTORY_KEYS: Dict[str, bytes] = {
    # ALENOC Electrum monitor directory, 2026-08.
    "a3c4a0c2b26bd753": bytes.fromhex(
        "4aee1362687878d14556dd922affe05d9611dc34636ec7346e588b9391a88ccf"),
}


class DirectoryError(ValueError):
    """The directory document is unusable and must be ignored."""


def _canonical_bytes(body: Mapping) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def verify_signed_directory(document: Mapping, *,
                            trusted_keys: Optional[Dict[str, bytes]] = None,
                            minimum_version: int = 0,
                            now: Optional[datetime.datetime] = None) -> dict:
    """Verify a signed directory snapshot and return its body."""
    keys = TRUSTED_DIRECTORY_KEYS if trusted_keys is None else trusted_keys
    if not keys:
        raise DirectoryError("this build trusts no directory signing key")
    if not isinstance(document, Mapping):
        raise DirectoryError("directory document must be an object")
    body = document.get("directory")
    signature = document.get("signature")
    if not isinstance(body, Mapping) or not isinstance(signature, Mapping):
        raise DirectoryError("directory document must contain directory and signature")
    if signature.get("algorithm") != "ed25519":
        raise DirectoryError("unsupported signature algorithm")
    key_id = signature.get("keyId")
    if key_id not in keys:
        raise DirectoryError(f"directory signed by unknown key id {key_id!r}")
    try:
        raw = base64.b64decode(signature.get("value", ""), validate=True)
    except Exception as exc:  # noqa: BLE001
        raise DirectoryError("signature is not valid base64") from exc

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        Ed25519PublicKey.from_public_bytes(keys[key_id]).verify(
            raw, _canonical_bytes(body))
    except InvalidSignature as exc:
        raise DirectoryError("directory signature does not verify") from exc

    if body.get("schemaVersion") != DIRECTORY_SCHEMA_VERSION:
        raise DirectoryError("unsupported directory schemaVersion")
    version = body.get("directoryVersion")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise DirectoryError("directoryVersion must be a positive integer")
    if version < minimum_version:
        raise DirectoryError(
            f"directory version {version} is older than the accepted "
            f"{minimum_version}; refusing a rollback")
    if not isinstance(body.get("servers"), list):
        raise DirectoryError("servers must be a list")

    expires_at = body.get("expiresAt")
    if expires_at:
        try:
            expiry = datetime.datetime.fromisoformat(expires_at)
        except ValueError as exc:
            raise DirectoryError("expiresAt is not a valid timestamp") from exc
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=datetime.timezone.utc)
        if (now or datetime.datetime.now(datetime.timezone.utc)) > expiry:
            raise DirectoryError("directory snapshot has expired")
    return dict(body)


def candidates(body: Mapping, *, prefer_encrypted: bool = True) -> List[dict]:
    """Turn a verified directory into connection candidates.

    The returned entries carry ``hint``, never a verdict, and nothing here marks
    an endpoint as usable.  Ordering is a convenience: entries the directory
    thought were healthy are tried first, because trying a likely-live server
    first is cheaper, not because the label was believed.
    """
    parsed = []
    for entry in body.get("servers", []):
        if not isinstance(entry, Mapping):
            continue
        hostname = entry.get("hostname")
        port = entry.get("port")
        transport = entry.get("transport")
        if not isinstance(hostname, str) or not hostname:
            continue
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            continue
        if transport not in ("TLS", "TCP"):
            continue
        parsed.append({
            "hostname": hostname,
            "port": port,
            "transport": transport,
            "hint": entry.get("security", "UNKNOWN"),
            "operatorGroup": entry.get("operatorGroup", "UNKNOWN"),
            "verified": False,  # nothing from a directory is ever pre-verified
        })

    def sort_key(candidate):
        healthy = 0 if candidate["hint"] == "SAFE" else 1
        encrypted = 0 if (prefer_encrypted and candidate["transport"] == "TLS") else 1
        return (encrypted, healthy, candidate["hostname"], candidate["port"])

    parsed.sort(key=sort_key)
    return parsed
