# Copyright (c) 2026, ALENOC
#
# The MIT License (MIT).  See LICENCE for details.

"""Signed safe-Core policy: what this wallet is willing to believe about a backend.

The rule this implements is deliberately not "a high enough version number".  It
is "this exact release, from this exact repository, at this exact commit, was
certified against the safety profile this wallet requires".  A newer Ravencoin
Core is not a safer one until somebody has tested it.

Trust flows one way.  A signed remote policy may add releases, and may restrict
or revoke anything including a built-in entry.  It may never rehabilitate a
release the built-in baseline refuses, and it may never introduce a new signing
key: the trusted keys live in this file and change only when the wallet is
updated.
"""

import base64
import datetime
import json
import os
import threading
from typing import Dict, Optional, Tuple

from .logging import Logger

REQUIRED_SAFETY_PROFILE = "rvn-consensus-2026-08-v1"
POLICY_SCHEMA_VERSION = 1
POLICY_CACHE_FILENAME = "safe-core-policy.json"
BASELINE_FILENAME = "core_safety_baseline.json"

#: Public keys allowed to sign a remote policy, as key id to raw Ed25519 bytes.
#:
#: Empty on purpose: no production policy-signing key has been published yet, so
#: this build accepts no remote policy at all and relies on the built-in
#: baseline.  Adding a key here is a wallet update, which is exactly the trust
#: transition it should be.  Two entries may coexist so a key can be rotated
#: without breaking older builds.
TRUSTED_POLICY_KEYS: Dict[str, bytes] = {}

_VALID_STATUSES = ("KNOWN_SAFE", "KNOWN_UNSAFE", "REVOKED")


class PolicyError(ValueError):
    """A policy document is unusable, so it must not be trusted or cached."""


def _canonical_bytes(body: dict) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _identity(entry: dict) -> Tuple[str, str]:
    return entry["repository"], entry["commit"]


def validate_body(body: dict) -> None:
    """Structural validation, independent of any signature."""
    if not isinstance(body, dict):
        raise PolicyError("policy body must be an object")
    if body.get("schemaVersion") != POLICY_SCHEMA_VERSION:
        raise PolicyError(f"unsupported policy schemaVersion "
                          f"{body.get('schemaVersion')!r}")
    version = body.get("policyVersion")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise PolicyError("policyVersion must be a positive integer")
    profile = body.get("safetyProfile")
    if not isinstance(profile, str) or not profile:
        raise PolicyError("safetyProfile must be a non-empty string")
    generated_at = body.get("generatedAt")
    if not isinstance(generated_at, str):
        raise PolicyError("generatedAt must be a string")
    try:
        datetime.datetime.fromisoformat(generated_at)
    except ValueError as exc:
        raise PolicyError("generatedAt is not a valid timestamp") from exc
    releases = body.get("releases")
    if not isinstance(releases, list):
        raise PolicyError("releases must be a list")
    seen = set()
    for entry in releases:
        if not isinstance(entry, dict):
            raise PolicyError("each release must be an object")
        for key in ("repository", "tag", "version", "commit", "status"):
            if not isinstance(entry.get(key), str) or not entry[key]:
                raise PolicyError(f"release entry is missing {key!r}")
        if entry["status"] not in _VALID_STATUSES:
            raise PolicyError(f"invalid release status {entry['status']!r}")
        if entry["status"] == "KNOWN_SAFE":
            certification = entry.get("certification")
            if not isinstance(certification, dict) \
                    or certification.get("result") != "PASS":
                raise PolicyError("a KNOWN_SAFE release must carry a passing "
                                  "certification")
        identity = _identity(entry)
        if identity in seen:
            raise PolicyError(f"duplicate release identity {identity}")
        seen.add(identity)


def verify_signed_policy(document: dict, *, trusted_keys: Optional[Dict[str, bytes]] = None,
                         minimum_policy_version: int = 0,
                         now: Optional[datetime.datetime] = None) -> dict:
    """Verify a signed policy document and return its body.

    Raises PolicyError on anything suspicious: unknown key, bad signature, bad
    schema, a version older than one already accepted, or an expired document.
    """
    keys = TRUSTED_POLICY_KEYS if trusted_keys is None else trusted_keys
    if not keys:
        raise PolicyError("this build trusts no policy signing key, so no remote "
                          "policy can be accepted")
    if not isinstance(document, dict):
        raise PolicyError("policy document must be an object")
    body = document.get("policy")
    signature = document.get("signature")
    if not isinstance(body, dict) or not isinstance(signature, dict):
        raise PolicyError("policy document must contain policy and signature")
    if signature.get("algorithm") != "ed25519":
        raise PolicyError(f"unsupported signature algorithm "
                          f"{signature.get('algorithm')!r}")
    key_id = signature.get("keyId")
    if key_id not in keys:
        raise PolicyError(f"policy signed by unknown key id {key_id!r}")
    try:
        raw_signature = base64.b64decode(signature.get("value", ""), validate=True)
    except Exception as exc:  # noqa: BLE001
        raise PolicyError("signature is not valid base64") from exc

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        Ed25519PublicKey.from_public_bytes(keys[key_id]).verify(
            raw_signature, _canonical_bytes(body))
    except InvalidSignature as exc:
        raise PolicyError("policy signature does not verify") from exc

    validate_body(body)
    if body["policyVersion"] < minimum_policy_version:
        raise PolicyError(
            f"policy version {body['policyVersion']} is older than the accepted "
            f"version {minimum_policy_version}; refusing a rollback")
    expires_at = body.get("expiresAt")
    if expires_at:
        try:
            expiry = datetime.datetime.fromisoformat(expires_at)
        except ValueError as exc:
            raise PolicyError("expiresAt is not a valid timestamp") from exc
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=datetime.timezone.utc)
        if (now or datetime.datetime.now(datetime.timezone.utc)) > expiry:
            raise PolicyError("policy has expired")
    return body


def load_baseline() -> dict:
    """Read the baseline shipped inside this wallet build."""
    path = os.path.join(os.path.dirname(__file__), BASELINE_FILENAME)
    with open(path, "r", encoding="utf-8") as handle:
        body = json.load(handle)
    validate_body(body)
    return body


def merge(baseline: dict, remote: Optional[dict]) -> dict:
    """Combine the baseline with a verified remote policy, restrictions winning."""
    validate_body(baseline)
    if remote is None:
        return baseline
    validate_body(remote)
    merged = {_identity(entry): dict(entry) for entry in baseline["releases"]}
    for entry in remote["releases"]:
        identity = _identity(entry)
        existing = merged.get(identity)
        if existing and existing["status"] in ("KNOWN_UNSAFE", "REVOKED") \
                and entry["status"] == "KNOWN_SAFE":
            continue
        merged[identity] = dict(entry)
    body = dict(remote)
    body["releases"] = sorted(merged.values(), key=lambda item: _identity(item))
    return body


def lookup(body: dict, repository: str, commit: str) -> Optional[dict]:
    """Find a release by identity.  Version is never part of the key."""
    if not repository or not commit:
        return None
    for entry in body.get("releases", []):
        if entry["repository"] == repository and entry["commit"] == commit.lower():
            return entry
    return None


def versions_present(body: dict, version: str) -> list:
    """Every certified identity that shares a version string.

    Used to tell "nobody has reviewed this release" apart from "a release with
    this version was certified, but not this one".
    """
    return [entry for entry in body.get("releases", [])
            if entry["version"] == version]


class PolicyStore(Logger):
    """Holds the effective policy: baseline, plus a cached verified remote one.

    Only verified policies are ever written to the cache, so a corrupt or hostile
    cache file cannot smuggle a release in.  If the cache is unreadable it is
    ignored and the baseline is used.
    """

    def __init__(self, cache_dir: Optional[str] = None):
        Logger.__init__(self)
        self.cache_dir = cache_dir
        self._lock = threading.RLock()
        self._baseline = load_baseline()
        self._remote: Optional[dict] = None
        if cache_dir:
            self._remote = self._load_cache()

    # ------------------------------------------------------------------ cache
    @property
    def _cache_path(self) -> Optional[str]:
        if not self.cache_dir:
            return None
        return os.path.join(self.cache_dir, POLICY_CACHE_FILENAME)

    def _load_cache(self) -> Optional[dict]:
        path = self._cache_path
        if not path or not os.path.exists(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as handle:
                document = json.load(handle)
            return verify_signed_policy(document)
        except (OSError, json.JSONDecodeError, PolicyError) as exc:
            self.logger.info(f"ignoring cached safe-Core policy: {exc}")
            return None

    def _write_cache(self, document: dict) -> None:
        path = self._cache_path
        if not path:
            return
        os.makedirs(self.cache_dir, exist_ok=True)
        temporary = path + ".tmp"
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump(document, handle, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)

    # ----------------------------------------------------------------- public
    @property
    def policy_version(self) -> int:
        with self._lock:
            if self._remote is not None:
                return int(self._remote["policyVersion"])
            return int(self._baseline["policyVersion"])

    def effective(self) -> dict:
        with self._lock:
            return merge(self._baseline, self._remote)

    def accept_remote(self, document: dict) -> dict:
        """Verify, anti-rollback, then persist.  Raises PolicyError on refusal."""
        with self._lock:
            body = verify_signed_policy(
                document, minimum_policy_version=self.policy_version)
            if body["safetyProfile"] != REQUIRED_SAFETY_PROFILE:
                raise PolicyError(
                    f"policy targets profile {body['safetyProfile']!r} but this "
                    f"wallet requires {REQUIRED_SAFETY_PROFILE!r}")
            self._remote = body
            try:
                self._write_cache(document)
            except OSError as exc:
                self.logger.info(f"could not cache the safe-Core policy: {exc}")
            return body


_default_store: Optional[PolicyStore] = None
_default_lock = threading.Lock()


def default_store(cache_dir: Optional[str] = None) -> PolicyStore:
    """Process-wide store, created on first use."""
    global _default_store
    with _default_lock:
        if _default_store is None:
            _default_store = PolicyStore(cache_dir)
        return _default_store


def default_policy() -> dict:
    return default_store().effective()
