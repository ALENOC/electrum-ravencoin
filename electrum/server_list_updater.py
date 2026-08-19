# Copyright (c) 2026, ALENOC
#
# The MIT License (MIT). See LICENCE for details.

"""Runtime refresh of the public ElectrumX server registry.

There are two remote inputs with deliberately different trust levels:

* ``servers.signed.json`` is an Ed25519-authenticated registry. A valid,
  non-expired, non-rolled-back registry is authoritative for both discovery
  endpoints and security-sensitive ``operatorGroup`` metadata.
* ``servers.json`` is an unsigned discovery fallback. It can add/update/remove
  ordinary endpoints, but every remote ``operatorGroup`` is discarded and the
  one compiled RavenTag anchor remains immutable.

The first client build that understands the signed registry must embed its
public key. After that, server/operator-group changes can be shipped by signing a
new higher ``registryVersion`` without recompiling the wallet. The signing
private key is never stored in this repository.

If no valid signed registry is available, the client deliberately falls back to
one compiled trusted anchor (``electrumx.raventag.com``) plus unsigned discovery.
With the quorum threshold still at two independent operators, sensitive actions
therefore fail closed until a second operator is present in a valid signed
registry.
"""

from __future__ import annotations

import base64
import copy
import datetime
import hashlib
import json
import os
import threading
import time
from typing import Any, Dict, Mapping, Optional, Tuple

from . import constants, util
from .interface import ServerAddr
from .logging import get_logger


_logger = get_logger(__name__)

REMOTE_SERVER_LIST_URL = (
    "https://raw.githubusercontent.com/ALENOC/electrum-ravencoin/"
    "master/electrum/servers.json"
)
REMOTE_SIGNED_REGISTRY_URL = (
    "https://raw.githubusercontent.com/ALENOC/electrum-ravencoin/"
    "master/electrum/servers.signed.json"
)

REFRESH_INTERVAL_SECONDS = 6 * 60 * 60
RETRY_INTERVAL_SECONDS = 5 * 60
STARTUP_POLL_SECONDS = 2
HTTP_TIMEOUT_SECONDS = 30
MAX_REMOTE_BYTES = 128 * 1024
MAX_REMOTE_SERVERS = 512

CACHE_SCHEMA_VERSION = 1
CACHE_FILENAME = "servers.remote.cache.json"
REGISTRY_SCHEMA_VERSION = 1
REGISTRY_CACHE_FILENAME = "servers.signed.cache.json"
REGISTRY_STATE_FILENAME = "servers.signed.state.json"
REGISTRY_SIGNATURE_DOMAIN = b"ALENOC-RVN-SERVER-REGISTRY-v1\x00"

# Dedicated server-registry signing key. Do not reuse the Core safety-policy
# key: the two trust domains must remain cryptographically independent.
# key id = first 16 hex chars of SHA-256(raw Ed25519 public key).
TRUSTED_REGISTRY_KEYS: Dict[str, bytes] = {
    "a81ee9b1b61a5dcf": bytes.fromhex(
        "65568ff8bab25eea4e038acafd93548918785deee6c26141ed861e4db2cc16f6"
    ),
}

# Only these hosts retain security-sensitive metadata when there is no valid
# signed registry. Once a signed registry is accepted, its signed operatorGroup
# assignments are authoritative and may add/remove/replace anchors dynamically.
TRUSTED_ANCHOR_HOSTS = frozenset({"electrumx.raventag.com"})

_COMPILED_SERVERS: Dict[str, dict] = copy.deepcopy(
    constants.RavencoinMainnet.DEFAULT_SERVERS
)
_BUILTIN_ANCHORS: Dict[str, dict] = {
    host: copy.deepcopy(_COMPILED_SERVERS[host])
    for host in TRUSTED_ANCHOR_HOSTS
    if host in _COMPILED_SERVERS
}
if set(_BUILTIN_ANCHORS) != set(TRUSTED_ANCHOR_HOSTS):
    missing = sorted(set(TRUSTED_ANCHOR_HOSTS) - set(_BUILTIN_ANCHORS))
    raise RuntimeError(f"trusted ElectrumX anchor missing from compiled list: {missing}")
for _host, _entry in _BUILTIN_ANCHORS.items():
    if not isinstance(_entry.get("operatorGroup"), str) or not _entry["operatorGroup"]:
        raise RuntimeError(f"trusted ElectrumX anchor {_host!r} has no operatorGroup")

_started = False
_start_lock = threading.Lock()


class ServerListError(ValueError):
    """The remote/cache server list or signed registry is unusable."""


def get_compiled_server_list() -> Dict[str, dict]:
    return copy.deepcopy(_COMPILED_SERVERS)


def get_builtin_anchor_list() -> Dict[str, dict]:
    return copy.deepcopy(_BUILTIN_ANCHORS)


def _validate_optional_text(
    entry: Mapping[str, Any], key: str, *, max_len: int
) -> Optional[str]:
    value = entry.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value or len(value) > max_len:
        raise ServerListError(f"invalid {key!r} field")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ServerListError(f"control character in {key!r}")
    return value


def _sanitize_server_list(value: Any, *, allow_operator_groups: bool) -> Dict[str, dict]:
    if not isinstance(value, dict):
        raise ServerListError("server list must be a JSON object")
    if not value:
        raise ServerListError("server list is empty")
    if len(value) > MAX_REMOTE_SERVERS:
        raise ServerListError("server list contains too many entries")

    sanitized: Dict[str, dict] = {}
    for host, raw_entry in value.items():
        if not isinstance(host, str) or not host or len(host) > 255:
            raise ServerListError("invalid server hostname")
        if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in host):
            raise ServerListError(
                f"invalid whitespace/control character in host {host!r}"
            )
        if "://" in host or "/" in host or "\\" in host:
            raise ServerListError(f"invalid server host {host!r}")
        if not isinstance(raw_entry, dict):
            raise ServerListError(f"entry for {host!r} must be an object")

        entry: Dict[str, str] = {}
        for protocol in ("s", "t"):
            if protocol not in raw_entry:
                continue
            port = raw_entry[protocol]
            if not isinstance(port, str) or not port.isascii() or not port.isdigit():
                raise ServerListError(f"invalid {protocol!r} port for {host!r}")
            port_number = int(port)
            if not 1 <= port_number <= 65535:
                raise ServerListError(f"out-of-range {protocol!r} port for {host!r}")
            try:
                ServerAddr(host, port_number, protocol=protocol)
            except (TypeError, ValueError, AssertionError) as exc:
                raise ServerListError(f"invalid endpoint {host!r}:{port}") from exc
            entry[protocol] = str(port_number)

        if not any(protocol in entry for protocol in ("s", "t")):
            raise ServerListError(f"entry for {host!r} has no supported protocol")

        for key, max_len in (
            ("version", 64),
            ("pruning", 32),
            ("backend_policy", 384),
        ):
            text = _validate_optional_text(raw_entry, key, max_len=max_len)
            if text is not None:
                entry[key] = text

        if allow_operator_groups:
            group = _validate_optional_text(raw_entry, "operatorGroup", max_len=128)
            if group is not None:
                entry["operatorGroup"] = group
        # SECURITY: unsigned callers never copy raw_entry["operatorGroup"].

        sanitized[host] = entry
    return sanitized


def sanitize_remote_server_list(value: Any) -> Dict[str, dict]:
    """Validate unsigned discovery JSON and strip all trust metadata."""
    return _sanitize_server_list(value, allow_operator_groups=False)


def sanitize_signed_server_list(value: Any) -> Dict[str, dict]:
    """Validate a signature-authenticated server list, preserving operator groups."""
    return _sanitize_server_list(value, allow_operator_groups=True)


def parse_remote_server_list(text: str) -> Dict[str, dict]:
    if not isinstance(text, str):
        raise ServerListError("remote response is not text")
    raw = text.encode("utf-8")
    if len(raw) > MAX_REMOTE_BYTES:
        raise ServerListError("remote server list exceeds size limit")
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ServerListError("remote server list is not valid JSON") from exc
    return sanitize_remote_server_list(value)


def build_effective_server_list(remote_servers: Mapping[str, dict]) -> Dict[str, dict]:
    """Build unsigned-fallback state: immutable RavenTag anchor + discovery."""
    sanitized = sanitize_remote_server_list(dict(remote_servers))
    effective = get_builtin_anchor_list()
    for host, entry in sanitized.items():
        if host in TRUSTED_ANCHOR_HOSTS:
            continue
        effective[host] = copy.deepcopy(entry)
    return effective


def build_signed_effective_server_list(servers: Mapping[str, dict]) -> Dict[str, dict]:
    """A verified signed registry is authoritative, including operatorGroup."""
    return sanitize_signed_server_list(dict(servers))


def _canonical_digest(value: Mapping[str, Any]) -> str:
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _registry_canonical_bytes(body: Mapping[str, Any]) -> bytes:
    return REGISTRY_SIGNATURE_DOMAIN + json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _parse_timestamp(value: Any, field: str) -> datetime.datetime:
    if not isinstance(value, str) or not value:
        raise ServerListError(f"{field} must be a non-empty timestamp string")
    try:
        parsed = datetime.datetime.fromisoformat(value)
    except ValueError as exc:
        raise ServerListError(f"{field} is not a valid timestamp") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed.astimezone(datetime.timezone.utc)


def validate_signed_registry_body(body: Any) -> Dict[str, Any]:
    if not isinstance(body, dict):
        raise ServerListError("registry body must be an object")
    if body.get("schemaVersion") != REGISTRY_SCHEMA_VERSION:
        raise ServerListError(
            f"unsupported registry schemaVersion {body.get('schemaVersion')!r}"
        )
    version = body.get("registryVersion")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise ServerListError("registryVersion must be a positive integer")
    generated_at = _parse_timestamp(body.get("generatedAt"), "generatedAt")
    expires_at = _parse_timestamp(body.get("expiresAt"), "expiresAt")
    if expires_at <= generated_at:
        raise ServerListError("expiresAt must be later than generatedAt")

    cleaned = dict(body)
    cleaned["servers"] = sanitize_signed_server_list(body.get("servers"))
    return cleaned


def verify_signed_registry(
    document: Any,
    *,
    trusted_keys: Optional[Dict[str, bytes]] = None,
    minimum_registry_version: int = 0,
    now: Optional[datetime.datetime] = None,
) -> Dict[str, Any]:
    """Verify signature, schema, expiry and anti-rollback version floor."""
    keys = TRUSTED_REGISTRY_KEYS if trusted_keys is None else trusted_keys
    if not keys:
        raise ServerListError("this build trusts no server-registry signing key")
    if not isinstance(document, dict):
        raise ServerListError("signed registry document must be an object")
    body = document.get("registry")
    signature = document.get("signature")
    if not isinstance(body, dict) or not isinstance(signature, dict):
        raise ServerListError("signed registry must contain registry and signature")
    if signature.get("algorithm") != "ed25519":
        raise ServerListError("unsupported registry signature algorithm")
    key_id = signature.get("keyId")
    if key_id not in keys:
        raise ServerListError(f"registry signed by unknown key id {key_id!r}")
    try:
        raw_signature = base64.b64decode(signature.get("value", ""), validate=True)
    except Exception as exc:  # noqa: BLE001
        raise ServerListError("registry signature is not valid base64") from exc

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        Ed25519PublicKey.from_public_bytes(keys[key_id]).verify(
            raw_signature, _registry_canonical_bytes(body)
        )
    except (InvalidSignature, ValueError) as exc:
        raise ServerListError("registry signature does not verify") from exc

    cleaned = validate_signed_registry_body(body)
    if cleaned["registryVersion"] < minimum_registry_version:
        raise ServerListError(
            f"registry version {cleaned['registryVersion']} is older than accepted "
            f"version {minimum_registry_version}; refusing rollback"
        )

    current = now or datetime.datetime.now(datetime.timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=datetime.timezone.utc)
    current = current.astimezone(datetime.timezone.utc)
    if current > _parse_timestamp(cleaned["expiresAt"], "expiresAt"):
        raise ServerListError("signed server registry has expired")
    return cleaned


def parse_signed_registry_text(
    text: str,
    *,
    minimum_registry_version: int = 0,
    now: Optional[datetime.datetime] = None,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    if not isinstance(text, str):
        raise ServerListError("signed registry response is not text")
    if len(text.encode("utf-8")) > MAX_REMOTE_BYTES:
        raise ServerListError("signed registry exceeds size limit")
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ServerListError("signed registry is not valid JSON") from exc
    body = verify_signed_registry(
        document,
        minimum_registry_version=minimum_registry_version,
        now=now,
    )
    return document, body


def apply_remote_server_list(remote_servers: Mapping[str, dict]) -> bool:
    effective = build_effective_server_list(remote_servers)
    return _apply_effective_server_list(effective)


def apply_signed_registry(body: Mapping[str, Any]) -> bool:
    validated = validate_signed_registry_body(dict(body))
    effective = build_signed_effective_server_list(validated["servers"])
    return _apply_effective_server_list(effective)


def _apply_effective_server_list(effective: Mapping[str, dict]) -> bool:
    effective_copy = copy.deepcopy(dict(effective))
    if constants.RavencoinMainnet.DEFAULT_SERVERS == effective_copy:
        return False
    constants.RavencoinMainnet.DEFAULT_SERVERS = effective_copy
    return True


def _cache_path(cache_dir: str) -> str:
    return os.path.join(cache_dir, CACHE_FILENAME)


def _registry_cache_path(cache_dir: str) -> str:
    return os.path.join(cache_dir, REGISTRY_CACHE_FILENAME)


def _registry_state_path(cache_dir: str) -> str:
    return os.path.join(cache_dir, REGISTRY_STATE_FILENAME)


def write_cached_remote_servers(
    cache_dir: str,
    remote_servers: Mapping[str, dict],
    *,
    fetched_at: Optional[int] = None,
) -> str:
    sanitized = sanitize_remote_server_list(dict(remote_servers))
    digest = _canonical_digest(sanitized)
    document = {
        "schemaVersion": CACHE_SCHEMA_VERSION,
        "source": REMOTE_SERVER_LIST_URL,
        "fetchedAt": int(time.time() if fetched_at is None else fetched_at),
        "sha256": digest,
        "servers": sanitized,
    }
    os.makedirs(cache_dir, exist_ok=True)
    path = _cache_path(cache_dir)
    temporary = path + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(document, handle, sort_keys=True, separators=(",", ":"))
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    return digest


def load_cached_remote_servers(
    cache_dir: str,
) -> Optional[Tuple[Dict[str, dict], str]]:
    path = _cache_path(cache_dir)
    try:
        if os.path.getsize(path) > MAX_REMOTE_BYTES * 2:
            raise ServerListError("cached server list exceeds size limit")
        with open(path, "r", encoding="utf-8") as handle:
            document = json.load(handle)
        if not isinstance(document, dict):
            raise ServerListError("cached server list is not an object")
        if document.get("schemaVersion") != CACHE_SCHEMA_VERSION:
            raise ServerListError("unsupported server-list cache schema")
        if document.get("source") != REMOTE_SERVER_LIST_URL:
            raise ServerListError("cached server list has wrong source")
        servers = sanitize_remote_server_list(document.get("servers"))
        digest = _canonical_digest(servers)
        if document.get("sha256") != digest:
            raise ServerListError("cached server list digest mismatch")
        return servers, digest
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError, ServerListError, TypeError, ValueError) as exc:
        _logger.info(f"ignoring invalid cached ElectrumX server list: {exc}")
        return None


def _load_registry_state(cache_dir: str) -> Tuple[int, Optional[str]]:
    path = _registry_state_path(cache_dir)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            state = json.load(handle)
        version = state.get("registryVersion")
        digest = state.get("registryDigest")
        if (
            not isinstance(version, int)
            or isinstance(version, bool)
            or version < 1
            or not isinstance(digest, str)
            or len(digest) != 64
        ):
            raise ServerListError("invalid signed-registry state")
        return version, digest
    except FileNotFoundError:
        return 0, None
    except (OSError, json.JSONDecodeError, ServerListError, TypeError, ValueError) as exc:
        _logger.info(f"ignoring invalid signed-registry state: {exc}")
        return 0, None


def _write_registry_state(
    cache_dir: str, body: Mapping[str, Any], document: Mapping[str, Any]
) -> None:
    digest = hashlib.sha256(_registry_canonical_bytes(body)).hexdigest()
    signature = document.get("signature") or {}
    state = {
        "registryVersion": int(body["registryVersion"]),
        "registryDigest": digest,
        "acceptedAt": int(time.time()),
        "keyId": signature.get("keyId"),
        "algorithm": signature.get("algorithm"),
    }
    os.makedirs(cache_dir, exist_ok=True)
    path = _registry_state_path(cache_dir)
    temporary = path + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(state, handle, sort_keys=True, separators=(",", ":"))
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _write_signed_registry_cache(cache_dir: str, document: Mapping[str, Any]) -> None:
    os.makedirs(cache_dir, exist_ok=True)
    path = _registry_cache_path(cache_dir)
    temporary = path + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(document, handle, sort_keys=True, separators=(",", ":"))
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def accept_signed_registry_document(
    cache_dir: Optional[str],
    document: Mapping[str, Any],
    *,
    now: Optional[datetime.datetime] = None,
) -> Dict[str, Any]:
    high_water = 0
    state_digest = None
    if cache_dir:
        high_water, state_digest = _load_registry_state(cache_dir)

    body = verify_signed_registry(
        dict(document),
        minimum_registry_version=high_water,
        now=now,
    )
    digest = hashlib.sha256(_registry_canonical_bytes(body)).hexdigest()
    if (
        high_water
        and body["registryVersion"] == high_water
        and state_digest is not None
        and digest != state_digest
    ):
        raise ServerListError(
            "same registryVersion has different signed contents; refusing equivocation"
        )

    if cache_dir:
        _write_signed_registry_cache(cache_dir, document)
        _write_registry_state(cache_dir, body, document)
    return body


def load_cached_signed_registry(
    cache_dir: str, *, now: Optional[datetime.datetime] = None
) -> Optional[Tuple[Dict[str, Any], Dict[str, Any]]]:
    path = _registry_cache_path(cache_dir)
    try:
        if os.path.getsize(path) > MAX_REMOTE_BYTES * 2:
            raise ServerListError("cached signed registry exceeds size limit")
        with open(path, "r", encoding="utf-8") as handle:
            document = json.load(handle)
        body = accept_signed_registry_document(cache_dir, document, now=now)
        return document, body
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError, ServerListError, TypeError, ValueError) as exc:
        _logger.info(f"ignoring invalid cached signed server registry: {exc}")
        return None


async def _read_limited_http_response(response: Any) -> str:
    """Read the full response while enforcing a hard post-decompression limit."""
    response.raise_for_status()
    content_length = response.content_length
    if content_length is not None and content_length > MAX_REMOTE_BYTES:
        raise ServerListError("remote server data exceeds advertised size limit")

    chunks = []
    total = 0
    while True:
        remaining = MAX_REMOTE_BYTES + 1 - total
        if remaining <= 0:
            raise ServerListError("remote server data exceeds size limit")
        chunk = await response.content.read(min(16 * 1024, remaining))
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_REMOTE_BYTES:
            raise ServerListError("remote server data exceeds size limit")
        chunks.append(chunk)

    raw = b"".join(chunks)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ServerListError("remote server data is not UTF-8") from exc


def _notify_network(network: Any) -> None:
    try:
        loop = network.asyncio_loop
        loop.call_soon_threadsafe(
            lambda: util.trigger_callback("servers", network.get_servers())
        )
        loop.call_soon_threadsafe(util.trigger_callback, "network_updated")
    except BaseException as exc:
        _logger.info(f"could not notify network about server-list refresh: {exc!r}")


def _fetch_text(network_cls: Any, url: str) -> str:
    return network_cls.send_http_on_proxy(
        "get",
        url,
        timeout=HTTP_TIMEOUT_SECONDS,
        on_finish=_read_limited_http_response,
    )


def _worker() -> None:
    from .network import Network  # lazy import: avoid network<->updater cycle

    loaded_cache_dirs = set()
    signed_body_by_cache: Dict[str, Dict[str, Any]] = {}
    next_attempt_at = 0.0

    while True:
        network = Network.get_instance()
        if (
            network is None
            or network.daemon is None
            or not getattr(network, "_was_started", False)
            or constants.net is not constants.RavencoinMainnet
        ):
            time.sleep(STARTUP_POLL_SECONDS)
            continue

        cache_dir = network.config.path or ""
        if cache_dir and cache_dir not in loaded_cache_dirs:
            loaded_cache_dirs.add(cache_dir)
            signed_cached = load_cached_signed_registry(cache_dir)
            if signed_cached is not None:
                _, body = signed_cached
                signed_body_by_cache[cache_dir] = body
                if apply_signed_registry(body):
                    _logger.info(
                        f"loaded signed ElectrumX registry v{body['registryVersion']} from cache"
                    )
                    _notify_network(network)
            else:
                cached = load_cached_remote_servers(cache_dir)
                if cached is not None:
                    cached_servers, _ = cached
                    if apply_remote_server_list(cached_servers):
                        _logger.info("loaded cached unsigned ElectrumX discovery list")
                        _notify_network(network)

        # Expiry is security state, not merely fetch-time validation. If a signed
        # registry expires while the app remains open, stop trusting its dynamic
        # operator groups and fall back to the compiled anchor + unsigned cache.
        active_body = signed_body_by_cache.get(cache_dir)
        if active_body is not None:
            expiry = _parse_timestamp(active_body["expiresAt"], "expiresAt")
            if datetime.datetime.now(datetime.timezone.utc) > expiry:
                signed_body_by_cache.pop(cache_dir, None)
                fallback = (
                    load_cached_remote_servers(cache_dir) if cache_dir else None
                )
                fallback_servers = fallback[0] if fallback else {}
                if fallback_servers:
                    changed = apply_remote_server_list(fallback_servers)
                else:
                    changed = _apply_effective_server_list(get_compiled_server_list())
                if changed:
                    _logger.info(
                        "signed ElectrumX registry expired; removed dynamic trust metadata"
                    )
                    _notify_network(network)

        now_mono = time.monotonic()
        if now_mono < next_attempt_at:
            time.sleep(min(STARTUP_POLL_SECONDS, next_attempt_at - now_mono))
            continue

        signed_error: Optional[BaseException] = None
        try:
            text = _fetch_text(Network, REMOTE_SIGNED_REGISTRY_URL)
            try:
                document = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ServerListError("signed registry is not valid JSON") from exc
            body = accept_signed_registry_document(cache_dir or None, document)
            changed = apply_signed_registry(body)
            signed_body_by_cache[cache_dir] = body
            if changed:
                _logger.info(
                    f"updated signed ElectrumX registry to v{body['registryVersion']}"
                )
                _notify_network(network)
            next_attempt_at = time.monotonic() + REFRESH_INTERVAL_SECONDS
            continue
        except BaseException as exc:
            signed_error = exc
            _logger.info(f"signed ElectrumX registry refresh failed: {exc!r}")

        # Never downgrade from a still-valid signed registry merely because the
        # network fetch failed. Keep the cached signed trust state.
        if cache_dir in signed_body_by_cache:
            next_attempt_at = time.monotonic() + RETRY_INTERVAL_SECONDS
            continue

        try:
            text = _fetch_text(Network, REMOTE_SERVER_LIST_URL)
            remote_servers = parse_remote_server_list(text)
            changed = apply_remote_server_list(remote_servers)
            if cache_dir:
                write_cached_remote_servers(cache_dir, remote_servers)
            if changed:
                _logger.info(
                    "updated unsigned ElectrumX discovery fallback; "
                    "operatorGroup metadata remains stripped"
                )
                _notify_network(network)
            # Signed registry failed, so retry sooner even though discovery worked.
            next_attempt_at = time.monotonic() + RETRY_INTERVAL_SECONDS
        except BaseException as exc:
            _logger.info(
                "ElectrumX discovery refresh failed; keeping current list: "
                f"signed={signed_error!r}, unsigned={exc!r}"
            )
            next_attempt_at = time.monotonic() + RETRY_INTERVAL_SECONDS


def start_server_list_updater() -> None:
    """Start exactly one daemon updater thread for this process."""
    global _started
    with _start_lock:
        if _started:
            return
        _started = True
        thread = threading.Thread(
            target=_worker,
            name="electrumx-server-list-updater",
            daemon=True,
        )
        thread.start()
