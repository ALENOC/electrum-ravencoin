# Copyright (c) 2026, the Electrum-Ravencoin community maintainers
#
# The MIT License (MIT).  See LICENCE for details.

"""Fail-closed eligibility policy for Ravencoin Electrum server backends.

``server.version`` identifies ElectrumX.  Only ``server.ravencoin_backend``
identifies the Ravencoin Core daemon, and that self-report remains a prerequisite
rather than a replacement for SPV/header validation.
"""

from dataclasses import dataclass
from enum import Enum
import re
import time
from typing import Any, Mapping, Optional, Tuple


MINIMUM_SAFE_CORE = (4, 8, 0, 0)
MINIMUM_SAFE_CORE_NUMBER = 4_080_000
MINIMUM_SAFE_CORE_STRING = "4.8.0"
MAX_BACKEND_EVIDENCE_AGE = 300
MAX_BACKEND_CLOCK_SKEW = 300
_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?$")
_SUBVERSION_RE = re.compile(r"^/Ravencoin:([0-9]+(?:\.[0-9]+){2,3})/$")


class BackendEligibilityState(str, Enum):
    SAFE_CORE_VERIFIED = "SAFE_CORE_VERIFIED"
    CORE_TOO_OLD = "CORE_TOO_OLD"
    CORE_VERSION_UNKNOWN = "CORE_VERSION_UNKNOWN"
    BACKEND_METHOD_UNAVAILABLE = "BACKEND_METHOD_UNAVAILABLE"
    BACKEND_MALFORMED = "BACKEND_MALFORMED"
    WRONG_NETWORK = "WRONG_NETWORK"
    BACKEND_UNSAFE = "BACKEND_UNSAFE"
    CHAIN_CONFLICT = "CHAIN_CONFLICT"
    UNREACHABLE = "UNREACHABLE"


class BackendEvidenceError(ValueError):
    def __init__(self, state: BackendEligibilityState, message: str):
        super().__init__(message)
        self.state = state


def parse_core_version_text(value: Any) -> Tuple[int, int, int, int]:
    if not isinstance(value, str) or not _VERSION_RE.fullmatch(value):
        raise BackendEvidenceError(
            BackendEligibilityState.CORE_VERSION_UNKNOWN,
            "backend Ravencoin Core version could not be verified",
        )
    parts = tuple(int(part) for part in value.split("."))
    return parts + (0,) * (4 - len(parts))


def parse_core_version_number(value: Any) -> Tuple[int, int, int, int]:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise BackendEvidenceError(
            BackendEligibilityState.CORE_VERSION_UNKNOWN,
            "backend Ravencoin Core numeric version could not be verified",
        )
    major, remainder = divmod(value, 1_000_000)
    minor, remainder = divmod(remainder, 10_000)
    patch, build = divmod(remainder, 100)
    return major, minor, patch, build


@dataclass(frozen=True)
class RavencoinBackendEvidence:
    server_name: str
    server_version: str
    core_name: str
    core_version: str
    core_version_tuple: Tuple[int, int, int, int]
    core_version_number: int
    core_subversion: str
    network: str
    blocks: int
    headers: int
    initial_block_download: Optional[bool]
    minimum_safe_core: str
    server_reports_core_safe: bool
    server_reports_network_match: bool
    server_reports_synchronized: bool
    server_reports_kawpow_height_validation: bool
    server_reports_checkpoint_4487775: bool
    observed_at: int

    @property
    def server_reports_compatible_backend(self) -> bool:
        """Compatibility claim only; chain validation is still required."""
        return classify_backend_evidence(self) == BackendEligibilityState.SAFE_CORE_VERIFIED


def _integer(value: Any, field: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise BackendEvidenceError(
            BackendEligibilityState.BACKEND_MALFORMED, "invalid {}".format(field)
        )
    return value


def _boolean(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise BackendEvidenceError(
            BackendEligibilityState.BACKEND_MALFORMED, "invalid {}".format(field)
        )
    return value


def _string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise BackendEvidenceError(
            BackendEligibilityState.BACKEND_MALFORMED, "invalid {}".format(field)
        )
    return value


def parse_ravencoin_backend_evidence(response: Any) -> RavencoinBackendEvidence:
    """Validate the exact sanitized server contract and conflicting evidence."""
    if not isinstance(response, Mapping):
        raise BackendEvidenceError(
            BackendEligibilityState.BACKEND_MALFORMED,
            "backend evidence must be an object",
        )
    backend = response.get("backend")
    compatibility = response.get("compatibility")
    if not isinstance(backend, Mapping) or not isinstance(compatibility, Mapping):
        raise BackendEvidenceError(
            BackendEligibilityState.BACKEND_MALFORMED,
            "backend evidence is missing nested objects",
        )

    core_version = backend.get("version")
    core_version_tuple = parse_core_version_text(core_version)
    core_version_number = backend.get("versionNumber")
    numeric_version_tuple = parse_core_version_number(core_version_number)
    if core_version_tuple != numeric_version_tuple:
        raise BackendEvidenceError(
            BackendEligibilityState.BACKEND_MALFORMED,
            "conflicting backend Core version fields",
        )

    core_subversion = _string(backend.get("subversion"), "backend.subversion")
    subversion_match = _SUBVERSION_RE.fullmatch(core_subversion)
    if not subversion_match or parse_core_version_text(subversion_match.group(1)) != core_version_tuple:
        raise BackendEvidenceError(
            BackendEligibilityState.BACKEND_MALFORMED,
            "backend Core subversion conflicts with its numeric version",
        )

    minimum_safe_core = compatibility.get("minimumSafeCore")
    minimum_safe_tuple = parse_core_version_text(minimum_safe_core)
    if minimum_safe_tuple != MINIMUM_SAFE_CORE:
        raise BackendEvidenceError(
            BackendEligibilityState.BACKEND_MALFORMED,
            "server reports an incompatible minimum safe Core policy",
        )

    blocks = _integer(backend.get("blocks"), "backend.blocks")
    headers = _integer(backend.get("headers"), "backend.headers")
    if headers < blocks:
        raise BackendEvidenceError(
            BackendEligibilityState.BACKEND_MALFORMED,
            "backend headers are below blocks",
        )
    ibd = backend.get("initialBlockDownload")
    if ibd not in (True, False, None):
        raise BackendEvidenceError(
            BackendEligibilityState.BACKEND_MALFORMED,
            "invalid backend.initialBlockDownload",
        )

    core_name = _string(backend.get("name"), "backend.name")
    if core_name != "Ravencoin Core":
        raise BackendEvidenceError(
            BackendEligibilityState.BACKEND_MALFORMED,
            "backend does not identify Ravencoin Core",
        )

    return RavencoinBackendEvidence(
        server_name=_string(response.get("server"), "server"),
        server_version=_string(response.get("serverVersion"), "serverVersion"),
        core_name=core_name,
        core_version=core_version,
        core_version_tuple=core_version_tuple,
        core_version_number=core_version_number,
        core_subversion=core_subversion,
        network=_string(backend.get("network"), "backend.network"),
        blocks=blocks,
        headers=headers,
        initial_block_download=ibd,
        minimum_safe_core=minimum_safe_core,
        server_reports_core_safe=_boolean(
            compatibility.get("coreSafe"), "compatibility.coreSafe"
        ),
        server_reports_network_match=_boolean(
            compatibility.get("networkMatches"), "compatibility.networkMatches"
        ),
        server_reports_synchronized=_boolean(
            compatibility.get("backendSynchronized"), "compatibility.backendSynchronized"
        ),
        server_reports_kawpow_height_validation=_boolean(
            compatibility.get("kawpowHeightValidation"),
            "compatibility.kawpowHeightValidation",
        ),
        server_reports_checkpoint_4487775=_boolean(
            compatibility.get("checkpoint4487775"), "compatibility.checkpoint4487775"
        ),
        observed_at=_integer(response.get("observedAt"), "observedAt", minimum=1),
    )


def classify_backend_evidence(
    evidence: RavencoinBackendEvidence, *, now: Optional[int] = None
) -> BackendEligibilityState:
    """Classify a structurally valid response under the mainnet safety policy."""
    if evidence.core_version_tuple < MINIMUM_SAFE_CORE:
        return BackendEligibilityState.CORE_TOO_OLD
    if evidence.network != "main" or not evidence.server_reports_network_match:
        return BackendEligibilityState.WRONG_NETWORK
    current_time = int(time.time() if now is None else now)
    if not current_time - MAX_BACKEND_EVIDENCE_AGE <= evidence.observed_at:
        return BackendEligibilityState.BACKEND_UNSAFE
    if evidence.observed_at > current_time + MAX_BACKEND_CLOCK_SKEW:
        return BackendEligibilityState.BACKEND_UNSAFE
    if not all((
        evidence.server_reports_core_safe,
        evidence.server_reports_synchronized,
        evidence.server_reports_kawpow_height_validation,
        evidence.server_reports_checkpoint_4487775,
        evidence.headers == evidence.blocks,
        evidence.initial_block_download is not True,
    )):
        return BackendEligibilityState.BACKEND_UNSAFE
    return BackendEligibilityState.SAFE_CORE_VERIFIED


def backend_rejection_message(
    evidence: RavencoinBackendEvidence, state: BackendEligibilityState
) -> str:
    if state == BackendEligibilityState.CORE_TOO_OLD:
        return (
            "Server rejected: Ravencoin Core {} is below the minimum safe version {}."
            .format(evidence.core_version, MINIMUM_SAFE_CORE_STRING)
        )
    if state == BackendEligibilityState.WRONG_NETWORK:
        return "Server rejected: backend reports the wrong Ravencoin network."
    return "Server rejected: backend Ravencoin Core safety requirements are not satisfied."
