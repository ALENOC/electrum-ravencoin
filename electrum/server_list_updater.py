# Copyright (c) 2026, ALENOC
#
# The MIT License (MIT). See LICENCE for details.

"""Runtime refresh of the public ElectrumX discovery list.

The repository copy of ``electrum/servers.json`` is useful operational data, but
it is *not* a trust root.  In particular, ``operatorGroup`` participates in the
independent-operator quorum enforced by :mod:`electrum.network`.  Treating an
unsigned, mutable GitHub file as authority for that field would let a repository
or GitHub compromise mint fake independent operators.

Consequently this module deliberately separates two concepts:

* the server entries compiled into the wallet are immutable security anchors;
* a validated remote ``servers.json`` may add/update ordinary discovery seeds,
  but may not replace/remove compiled anchors and may never grant an
  ``operatorGroup`` to a remotely introduced host.

That gives already-built clients a useful live server directory without moving
any security boundary out of the binary.  A future *signed* server registry can
safely make the trust metadata itself updateable.
"""

from __future__ import annotations

import copy
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
REFRESH_INTERVAL_SECONDS = 6 * 60 * 60
RETRY_INTERVAL_SECONDS = 5 * 60
STARTUP_POLL_SECONDS = 2
HTTP_TIMEOUT_SECONDS = 30
MAX_REMOTE_BYTES = 128 * 1024
MAX_REMOTE_SERVERS = 512
CACHE_SCHEMA_VERSION = 1
CACHE_FILENAME = "servers.remote.cache.json"

# Capture the exact list shipped by this build before any runtime refresh can
# replace the class attribute.  This is the immutable security baseline for
# this process.  New remote entries are intentionally not allowed to inherit
# or invent operator identity.
_BUILTIN_SERVERS: Dict[str, dict] = copy.deepcopy(
    constants.RavencoinMainnet.DEFAULT_SERVERS
)

_started = False
_start_lock = threading.Lock()


class ServerListError(ValueError):
    """The remote/cache server list is malformed or outside policy."""


def get_builtin_server_list() -> Dict[str, dict]:
    """Return a defensive copy of the server anchors compiled into this build."""
    return copy.deepcopy(_BUILTIN_SERVERS)


def _validate_optional_text(entry: Mapping[str, Any], key: str, *, max_len: int) -> Optional[str]:
    value = entry.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value or len(value) > max_len:
        raise ServerListError(f"invalid {key!r} field")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ServerListError(f"control character in {key!r}")
    return value


def sanitize_remote_server_list(value: Any) -> Dict[str, dict]:
    """Validate untrusted JSON and return only non-security server metadata.

    ``operatorGroup`` is intentionally ignored even when present.  Ports are
    validated by ``ServerAddr`` so DNS names, IP literals, and onion hosts obey
    the same parser the network layer will use later.
    """
    if not isinstance(value, dict):
        raise ServerListError("server list must be a JSON object")
    if not value:
        raise ServerListError("remote server list is empty")
    if len(value) > MAX_REMOTE_SERVERS:
        raise ServerListError("remote server list contains too many entries")

    sanitized: Dict[str, dict] = {}
    for host, raw_entry in value.items():
        if not isinstance(host, str) or not host or len(host) > 255:
            raise ServerListError("invalid server hostname")
        if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in host):
            raise ServerListError(f"invalid whitespace/control character in host {host!r}")
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

        version = _validate_optional_text(raw_entry, "version", max_len=64)
        pruning = _validate_optional_text(raw_entry, "pruning", max_len=32)
        backend_policy = _validate_optional_text(
            raw_entry, "backend_policy", max_len=256
        )
        if version is not None:
            entry["version"] = version
        if pruning is not None:
            entry["pruning"] = pruning
        if backend_policy is not None:
            entry["backend_policy"] = backend_policy

        # SECURITY: never copy raw_entry['operatorGroup'] here.
        sanitized[host] = entry

    return sanitized


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
    """Merge remote discovery entries into the immutable compiled baseline.

    A compiled host always wins in full.  This prevents an unsigned remote file
    from changing its port, removing it, or altering security metadata.  Hosts
    first introduced remotely are fully updateable/removable on later refreshes
    but cannot count as independent security operators.
    """
    sanitized = sanitize_remote_server_list(dict(remote_servers))
    effective = get_builtin_server_list()
    for host, entry in sanitized.items():
        if host in _BUILTIN_SERVERS:
            continue
        effective[host] = copy.deepcopy(entry)
    return effective


def _canonical_digest(servers: Mapping[str, dict]) -> str:
    payload = json.dumps(
        servers, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def apply_remote_server_list(remote_servers: Mapping[str, dict]) -> bool:
    """Atomically publish an effective list to the mainnet network class."""
    effective = build_effective_server_list(remote_servers)
    if constants.RavencoinMainnet.DEFAULT_SERVERS == effective:
        return False
    # Replace the object rather than mutating it while network threads may be
    # iterating. constants.net is the class object, so mainnet readers see the
    # new mapping immediately.
    constants.RavencoinMainnet.DEFAULT_SERVERS = effective
    return True


def _cache_path(cache_dir: str) -> str:
    return os.path.join(cache_dir, CACHE_FILENAME)


def write_cached_remote_servers(
    cache_dir: str, remote_servers: Mapping[str, dict], *, fetched_at: Optional[int] = None
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


def load_cached_remote_servers(cache_dir: str) -> Optional[Tuple[Dict[str, dict], str]]:
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


async def _read_limited_http_response(response: Any) -> str:
    """Read at most MAX_REMOTE_BYTES, including decompressed response bytes."""
    response.raise_for_status()
    content_length = response.content_length
    if content_length is not None and content_length > MAX_REMOTE_BYTES:
        raise ServerListError("remote server list exceeds advertised size limit")
    raw = await response.content.read(MAX_REMOTE_BYTES + 1)
    if len(raw) > MAX_REMOTE_BYTES:
        raise ServerListError("remote server list exceeds size limit")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ServerListError("remote server list is not UTF-8") from exc


def _notify_network(network: Any) -> None:
    try:
        loop = network.asyncio_loop
        loop.call_soon_threadsafe(
            lambda: util.trigger_callback("servers", network.get_servers())
        )
        loop.call_soon_threadsafe(util.trigger_callback, "network_updated")
    except BaseException as exc:  # notification failure must not kill updater
        _logger.info(f"could not notify network about server-list refresh: {exc!r}")


def _worker() -> None:
    # Import lazily to avoid a network<->updater import cycle at package startup.
    from .network import Network

    loaded_cache_dirs = set()
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

        cache_dir = network.config.path
        if cache_dir and cache_dir not in loaded_cache_dirs:
            loaded_cache_dirs.add(cache_dir)
            cached = load_cached_remote_servers(cache_dir)
            if cached is not None:
                cached_servers, _ = cached
                if apply_remote_server_list(cached_servers):
                    _logger.info("loaded cached runtime ElectrumX server list")
                    _notify_network(network)

        now = time.monotonic()
        if now < next_attempt_at:
            time.sleep(min(STARTUP_POLL_SECONDS, next_attempt_at - now))
            continue

        try:
            text = Network.send_http_on_proxy(
                "get",
                REMOTE_SERVER_LIST_URL,
                timeout=HTTP_TIMEOUT_SECONDS,
                on_finish=_read_limited_http_response,
            )
            remote_servers = parse_remote_server_list(text)
            changed = apply_remote_server_list(remote_servers)
            if cache_dir:
                write_cached_remote_servers(cache_dir, remote_servers)
            if changed:
                _logger.info(
                    f"updated runtime ElectrumX server list from "
                    f"{REMOTE_SERVER_LIST_URL}"
                )
                _notify_network(network)
            next_attempt_at = time.monotonic() + REFRESH_INTERVAL_SECONDS
        except BaseException as exc:
            # Availability only: retain the last validated cache/effective list.
            # Never clear the compiled fallback because a remote update failed.
            _logger.info(f"ElectrumX server-list refresh failed; keeping current list: {exc!r}")
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
