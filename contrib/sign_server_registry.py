#!/usr/bin/env python3
"""Create electrum/servers.signed.json using an offline Ed25519 private key.

This signer is intentionally standalone: it does not import the Electrum package
or initialize wallet/network code. It reads the registry policy constants from
``electrum/server_list_updater.py`` as source text using a restricted AST parser,
so offline signing needs only Python and ``cryptography``.

The private key must remain outside Git. The helper refuses a key whose public
half is not already present in the client's TRUSTED_REGISTRY_KEYS mapping.
"""

import argparse
import ast
import base64
import datetime
import hashlib
import json
import os
from typing import Any, Dict, Mapping, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
UPDATER_SOURCE = os.path.join(ROOT, "electrum", "server_list_updater.py")
MAX_REMOTE_SERVERS = 512


def _assignment_value(tree: ast.Module, name: str) -> ast.AST:
    for node in tree.body:
        target = None
        value = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            target = node.target
            value = node.value
        if isinstance(target, ast.Name) and target.id == name and value is not None:
            return value
    raise SystemExit(f"could not locate {name} in {UPDATER_SOURCE}")


def _parse_trusted_keys(node: ast.AST) -> Dict[str, bytes]:
    if not isinstance(node, ast.Dict):
        raise SystemExit("TRUSTED_REGISTRY_KEYS must be a literal dictionary")

    trusted: Dict[str, bytes] = {}
    for key_node, value_node in zip(node.keys, node.values):
        try:
            key_id = ast.literal_eval(key_node)
        except (ValueError, TypeError) as exc:
            raise SystemExit("invalid registry key id in client source") from exc
        if not isinstance(key_id, str) or len(key_id) != 16:
            raise SystemExit("registry key id must be a 16-character string")

        if not (
            isinstance(value_node, ast.Call)
            and isinstance(value_node.func, ast.Attribute)
            and isinstance(value_node.func.value, ast.Name)
            and value_node.func.value.id == "bytes"
            and value_node.func.attr == "fromhex"
            and len(value_node.args) == 1
            and not value_node.keywords
        ):
            raise SystemExit(
                "TRUSTED_REGISTRY_KEYS values must use bytes.fromhex(<literal>)"
            )
        try:
            public_hex = ast.literal_eval(value_node.args[0])
        except (ValueError, TypeError) as exc:
            raise SystemExit("invalid public-key hex literal in client source") from exc
        if not isinstance(public_hex, str):
            raise SystemExit("public key hex must be a string literal")
        try:
            public_raw = bytes.fromhex(public_hex)
        except ValueError as exc:
            raise SystemExit("public key hex in client source is invalid") from exc
        if len(public_raw) != 32:
            raise SystemExit("Ed25519 public key in client source must be 32 bytes")
        derived_id = hashlib.sha256(public_raw).hexdigest()[:16]
        if derived_id != key_id:
            raise SystemExit(
                f"client registry key id {key_id} does not match public key "
                f"(expected {derived_id})"
            )
        trusted[key_id] = public_raw

    if not trusted:
        raise SystemExit("client source contains no trusted registry keys")
    return trusted


def load_registry_policy(path: str) -> Tuple[int, bytes, Dict[str, bytes]]:
    with open(path, "r", encoding="utf-8") as handle:
        tree = ast.parse(handle.read(), filename=path)

    try:
        schema_version = ast.literal_eval(
            _assignment_value(tree, "REGISTRY_SCHEMA_VERSION")
        )
        signature_domain = ast.literal_eval(
            _assignment_value(tree, "REGISTRY_SIGNATURE_DOMAIN")
        )
    except (ValueError, TypeError) as exc:
        raise SystemExit("registry policy constants are not literal values") from exc

    if not isinstance(schema_version, int) or isinstance(schema_version, bool):
        raise SystemExit("REGISTRY_SCHEMA_VERSION must be an integer")
    if not isinstance(signature_domain, bytes) or not signature_domain:
        raise SystemExit("REGISTRY_SIGNATURE_DOMAIN must be non-empty bytes")

    trusted_keys = _parse_trusted_keys(
        _assignment_value(tree, "TRUSTED_REGISTRY_KEYS")
    )
    return schema_version, signature_domain, trusted_keys


def _validate_optional_text(
    entry: Mapping[str, Any], key: str, *, max_len: int
):
    value = entry.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value or len(value) > max_len:
        raise SystemExit(f"invalid {key!r} field")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise SystemExit(f"control character in {key!r}")
    return value


def sanitize_signed_server_list(value: Any) -> Dict[str, dict]:
    """Perform signer-side structural validation without importing Electrum."""
    if not isinstance(value, dict):
        raise SystemExit("server list must be a JSON object")
    if not value:
        raise SystemExit("server list is empty")
    if len(value) > MAX_REMOTE_SERVERS:
        raise SystemExit("server list contains too many entries")

    sanitized: Dict[str, dict] = {}
    for host, raw_entry in value.items():
        if not isinstance(host, str) or not host or len(host) > 255:
            raise SystemExit("invalid server hostname")
        if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in host):
            raise SystemExit(
                f"invalid whitespace/control character in host {host!r}"
            )
        if "://" in host or "/" in host or "\\" in host:
            raise SystemExit(f"invalid server host {host!r}")
        if not isinstance(raw_entry, dict):
            raise SystemExit(f"entry for {host!r} must be an object")

        entry: Dict[str, str] = {}
        for protocol in ("s", "t"):
            if protocol not in raw_entry:
                continue
            port = raw_entry[protocol]
            if (
                not isinstance(port, str)
                or not port.isascii()
                or not port.isdigit()
            ):
                raise SystemExit(f"invalid {protocol!r} port for {host!r}")
            port_number = int(port)
            if not 1 <= port_number <= 65535:
                raise SystemExit(f"out-of-range {protocol!r} port for {host!r}")
            entry[protocol] = str(port_number)

        if not any(protocol in entry for protocol in ("s", "t")):
            raise SystemExit(f"entry for {host!r} has no supported protocol")

        for key, max_len in (
            ("version", 64),
            ("pruning", 32),
            ("backend_policy", 384),
        ):
            text = _validate_optional_text(raw_entry, key, max_len=max_len)
            if text is not None:
                entry[key] = text

        group = _validate_optional_text(raw_entry, "operatorGroup", max_len=128)
        if group is not None:
            entry["operatorGroup"] = group

        sanitized[host] = entry

    return sanitized


def canonical_bytes(body: dict, signature_domain: bytes) -> bytes:
    return signature_domain + json.dumps(
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


def public_key_id(key: Ed25519PrivateKey) -> Tuple[str, bytes]:
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
        help="PEM Ed25519 private key stored outside Git",
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

    schema_version, signature_domain, trusted_keys = load_registry_policy(
        UPDATER_SOURCE
    )

    with open(args.input, "r", encoding="utf-8") as handle:
        servers = sanitize_signed_server_list(json.load(handle))

    private_key = load_private_key(args.key)
    key_id, public_raw = public_key_id(private_key)
    expected = trusted_keys.get(key_id)
    if expected is None or expected != public_raw:
        raise SystemExit(
            f"key {key_id} is not a trusted server-registry signing key "
            "in electrum/server_list_updater.py"
        )

    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    expires = now + datetime.timedelta(days=args.expires_days)
    body = {
        "schemaVersion": schema_version,
        "registryVersion": args.registry_version,
        "generatedAt": now.isoformat(),
        "expiresAt": expires.isoformat(),
        "servers": servers,
    }
    signature = private_key.sign(canonical_bytes(body, signature_domain))
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
