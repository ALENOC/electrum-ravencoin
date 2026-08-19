#!/usr/bin/env python3
"""Offline Ed25519 signing for Electrum-Ravencoin release manifests."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


DOMAIN = b"ALENOC-ELECTRUM-RAVENCOIN-RELEASE-v1\x00"
DEFAULT_PRIVATE_KEY = Path(".server-registry-key/release-signing-ed25519-private.pem")
DEFAULT_PUBLIC_INFO = Path("RELEASE_SIGNING_PUBKEY.json")


def _key_id(raw_public_key: bytes) -> str:
    return hashlib.sha256(raw_public_key).hexdigest()[:16]


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit(f"{path}: expected an Ed25519 private key")
    return key


def _raw_public_key(key: Ed25519PrivateKey | Ed25519PublicKey) -> bytes:
    public = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    return public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _load_public_info(path: Path) -> tuple[str, bytes]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    if obj.get("algorithm") != "ed25519":
        raise SystemExit(f"{path}: unsupported algorithm")
    raw = bytes.fromhex(obj["publicKeyHex"])
    if len(raw) != 32:
        raise SystemExit(f"{path}: Ed25519 public key must be 32 bytes")
    expected_id = _key_id(raw)
    if obj.get("keyId") != expected_id:
        raise SystemExit(f"{path}: keyId does not match publicKeyHex")
    return expected_id, raw


def command_key_info(args: argparse.Namespace) -> None:
    private = _load_private_key(args.key)
    raw = _raw_public_key(private)
    print(f"PUBLIC_KEY_HEX = {raw.hex()}")
    print(f"KEY_ID = {_key_id(raw)}")


def command_export_public(args: argparse.Namespace) -> None:
    private = _load_private_key(args.key)
    raw = _raw_public_key(private)
    obj = {
        "schemaVersion": 1,
        "algorithm": "ed25519",
        "keyId": _key_id(raw),
        "publicKeyHex": raw.hex(),
    }
    if args.output.exists() and not args.force:
        raise SystemExit(f"{args.output} already exists; use --force to replace it")
    args.output.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {args.output} ({obj['keyId']})")


def command_sign(args: argparse.Namespace) -> None:
    private = _load_private_key(args.key)
    raw_public = _raw_public_key(private)
    key_id = _key_id(raw_public)

    if args.public_info.exists():
        trusted_id, trusted_raw = _load_public_info(args.public_info)
        if trusted_id != key_id or trusted_raw != raw_public:
            raise SystemExit("private key does not match committed RELEASE_SIGNING_PUBKEY.json")

    manifest = args.manifest.read_bytes()
    signature = private.sign(DOMAIN + manifest)
    obj = {
        "schemaVersion": 1,
        "algorithm": "ed25519",
        "domain": "ALENOC-ELECTRUM-RAVENCOIN-RELEASE-v1",
        "keyId": key_id,
        "manifest": args.manifest.name,
        "manifestSha256": hashlib.sha256(manifest).hexdigest(),
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    args.output.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"signed {args.manifest} with key {key_id} -> {args.output}")


def command_verify(args: argparse.Namespace) -> None:
    key_id, raw_public = _load_public_info(args.public_info)
    obj = json.loads(args.signature.read_text(encoding="utf-8"))
    if obj.get("schemaVersion") != 1 or obj.get("algorithm") != "ed25519":
        raise SystemExit("unsupported release signature format")
    if obj.get("keyId") != key_id:
        raise SystemExit("signature keyId is not the trusted release key")
    if obj.get("manifest") != args.manifest.name:
        raise SystemExit("signature manifest name does not match")
    manifest = args.manifest.read_bytes()
    digest = hashlib.sha256(manifest).hexdigest()
    if obj.get("manifestSha256") != digest:
        raise SystemExit("manifest digest does not match signature metadata")
    signature = base64.b64decode(obj["signature"], validate=True)
    try:
        Ed25519PublicKey.from_public_bytes(raw_public).verify(signature, DOMAIN + manifest)
    except Exception as e:
        raise SystemExit("release manifest signature verification failed") from e
    print(f"OK: {args.manifest} is signed by trusted release key {key_id}")


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("key-info")
    p.add_argument("--key", type=Path, default=DEFAULT_PRIVATE_KEY)
    p.set_defaults(func=command_key_info)

    p = sub.add_parser("export-public")
    p.add_argument("--key", type=Path, default=DEFAULT_PRIVATE_KEY)
    p.add_argument("--output", type=Path, default=DEFAULT_PUBLIC_INFO)
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=command_export_public)

    p = sub.add_parser("sign")
    p.add_argument("--key", type=Path, default=DEFAULT_PRIVATE_KEY)
    p.add_argument("--manifest", type=Path, default=Path("SHA256SUMS"))
    p.add_argument("--public-info", type=Path, default=DEFAULT_PUBLIC_INFO)
    p.add_argument("--output", type=Path, default=Path("SHA256SUMS.ed25519.json"))
    p.set_defaults(func=command_sign)

    p = sub.add_parser("verify")
    p.add_argument("--manifest", type=Path, default=Path("SHA256SUMS"))
    p.add_argument("--signature", type=Path, default=Path("SHA256SUMS.ed25519.json"))
    p.add_argument("--public-info", type=Path, default=DEFAULT_PUBLIC_INFO)
    p.set_defaults(func=command_verify)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
