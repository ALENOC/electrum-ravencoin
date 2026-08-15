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
    # Identity and policy states.  A version number alone can no longer make a
    # backend eligible: the exact certified identity has to be in the policy.
    CORE_KNOWN_UNSAFE = "CORE_KNOWN_UNSAFE"
    CORE_REVOKED = "CORE_REVOKED"
    CORE_UNREVIEWED_VERSION = "CORE_UNREVIEWED_VERSION"
    CORE_IDENTITY_UNKNOWN = "CORE_IDENTITY_UNKNOWN"
    CORE_IDENTITY_CONFLICT = "CORE_IDENTITY_CONFLICT"


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
    # Reported backend identity.  Absent on servers predating the identity
    # capability, which makes them ineligible under the certified-release model.
    identity_evidence: str = "UNKNOWN"
    source_repository: Optional[str] = None
    source_tag: Optional[str] = None
    source_commit: Optional[str] = None
    artifact_sha256: Optional[str] = None
    safety_profile: Optional[str] = None

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
        **_parse_identity(backend.get("identity"), compatibility),
    )


_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_KNOWN_EVIDENCE_LEVELS = (
    "BUILD_IDENTITY_VERIFIED", "BUILD_IDENTITY_ATTESTED", "VERSION_ONLY", "UNKNOWN",
)


def _parse_identity(identity: Any, compatibility: Mapping[str, Any]) -> dict:
    """Read the reported backend identity without inventing certainty.

    A server that reports nothing gets UNKNOWN, which is not an error: it is a
    server this wallet cannot place in its policy, and it will be refused for that
    reason rather than for being malformed.
    """
    parsed = {
        "identity_evidence": "UNKNOWN",
        "source_repository": None,
        "source_tag": None,
        "source_commit": None,
        "artifact_sha256": None,
        "safety_profile": None,
    }
    profile = compatibility.get("safetyProfile")
    if profile is not None:
        if not isinstance(profile, str) or not profile:
            raise BackendEvidenceError(
                BackendEligibilityState.BACKEND_MALFORMED,
                "invalid compatibility.safetyProfile",
            )
        parsed["safety_profile"] = profile

    if identity is None:
        return parsed
    if not isinstance(identity, Mapping):
        raise BackendEvidenceError(
            BackendEligibilityState.BACKEND_MALFORMED, "invalid backend.identity"
        )

    level = identity.get("evidence")
    if not isinstance(level, str) or level not in _KNOWN_EVIDENCE_LEVELS:
        raise BackendEvidenceError(
            BackendEligibilityState.BACKEND_MALFORMED,
            "invalid backend.identity.evidence",
        )
    parsed["identity_evidence"] = level

    repository = identity.get("sourceRepository")
    commit = identity.get("sourceCommit")
    tag = identity.get("sourceTag")
    artifact = identity.get("artifactSha256")
    if repository is not None:
        if not isinstance(repository, str) or not repository:
            raise BackendEvidenceError(
                BackendEligibilityState.BACKEND_MALFORMED,
                "invalid backend.identity.sourceRepository",
            )
        parsed["source_repository"] = repository
    if commit is not None:
        if not isinstance(commit, str) or not _COMMIT_RE.fullmatch(commit.lower()):
            raise BackendEvidenceError(
                BackendEligibilityState.BACKEND_MALFORMED,
                "invalid backend.identity.sourceCommit",
            )
        parsed["source_commit"] = commit.lower()
    if tag is not None:
        if not isinstance(tag, str) or not tag:
            raise BackendEvidenceError(
                BackendEligibilityState.BACKEND_MALFORMED,
                "invalid backend.identity.sourceTag",
            )
        parsed["source_tag"] = tag
    if artifact is not None:
        if not isinstance(artifact, str) or not _SHA256_RE.fullmatch(artifact.lower()):
            raise BackendEvidenceError(
                BackendEligibilityState.BACKEND_MALFORMED,
                "invalid backend.identity.artifactSha256",
            )
        parsed["artifact_sha256"] = artifact.lower()

    if level in ("BUILD_IDENTITY_VERIFIED", "BUILD_IDENTITY_ATTESTED") \
            and (parsed["source_repository"] is None or parsed["source_commit"] is None):
        raise BackendEvidenceError(
            BackendEligibilityState.BACKEND_MALFORMED,
            "backend claims an identity evidence level without reporting an identity",
        )
    return parsed


def classify_backend_evidence(
    evidence: RavencoinBackendEvidence, *, now: Optional[int] = None,
    policy: Optional[Mapping[str, Any]] = None,
) -> BackendEligibilityState:
    """Classify a structurally valid response under the mainnet safety policy.

    Order matters.  Cheap disqualifications first, then the safety flags, then the
    question that actually decides trust: is this exact release identity certified
    in the signed policy this wallet holds?

    A version number never grants eligibility.  It is kept as a floor, because a
    release below 4.8.0 predates the incident fix and can be refused without
    consulting anything, and as a diagnostic for the message shown to the user.
    """
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
    return classify_release_identity(evidence, policy=policy)


def classify_release_identity(
    evidence: RavencoinBackendEvidence, *,
    policy: Optional[Mapping[str, Any]] = None,
) -> BackendEligibilityState:
    """Decide eligibility from the certified-release policy, by exact identity."""
    from . import core_safety_policy

    if policy is None:
        policy = core_safety_policy.default_policy()

    if evidence.safety_profile is not None \
            and evidence.safety_profile != core_safety_policy.REQUIRED_SAFETY_PROFILE:
        # The server was certified, or claims to have been, against a different
        # profile than this wallet requires.  Not a lie, not good enough either.
        return BackendEligibilityState.CORE_UNREVIEWED_VERSION

    if not evidence.source_repository or not evidence.source_commit:
        return BackendEligibilityState.CORE_IDENTITY_UNKNOWN

    entry = core_safety_policy.lookup(
        policy, evidence.source_repository, evidence.source_commit)
    if entry is None:
        # Nothing certified at this identity.  Distinguish "this release was never
        # reviewed" from "a release with this version was certified, but not this
        # build", which is the shape an impostor takes.
        same_version = core_safety_policy.versions_present(policy,
                                                           evidence.core_version)
        if same_version:
            return BackendEligibilityState.CORE_IDENTITY_CONFLICT
        return BackendEligibilityState.CORE_UNREVIEWED_VERSION

    if entry["status"] == "REVOKED":
        return BackendEligibilityState.CORE_REVOKED
    if entry["status"] == "KNOWN_UNSAFE":
        return BackendEligibilityState.CORE_KNOWN_UNSAFE

    certification = entry.get("certification") or {}
    if certification.get("profile") != core_safety_policy.REQUIRED_SAFETY_PROFILE:
        return BackendEligibilityState.CORE_UNREVIEWED_VERSION
    if entry["version"] != evidence.core_version:
        # The certified identity exists but the running daemon reports a different
        # version than what was certified at that commit.
        return BackendEligibilityState.CORE_IDENTITY_CONFLICT
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
    if state == BackendEligibilityState.CORE_UNREVIEWED_VERSION:
        return (
            "Server rejected: backend Ravencoin Core {} has not been certified as safe "
            "yet. A newer release is not automatically a safer one; it becomes usable "
            "once it passes certification and appears in a signed policy update."
            .format(evidence.core_version)
        )
    if state == BackendEligibilityState.CORE_IDENTITY_CONFLICT:
        return (
            "Server rejected: the backend claims Ravencoin Core {} but not the exact "
            "certified build. A different commit or repository is a different release."
            .format(evidence.core_version)
        )
    if state == BackendEligibilityState.CORE_IDENTITY_UNKNOWN:
        return (
            "Server rejected: the server does not report which Ravencoin Core build it "
            "runs, so it cannot be matched against the certified-release policy."
        )
    if state == BackendEligibilityState.CORE_REVOKED:
        return (
            "Server rejected: backend Ravencoin Core {} was certified once and has "
            "since been revoked.".format(evidence.core_version)
        )
    if state == BackendEligibilityState.CORE_KNOWN_UNSAFE:
        return (
            "Server rejected: backend Ravencoin Core {} is known to be unsafe."
            .format(evidence.core_version)
        )
    return "Server rejected: backend Ravencoin Core safety requirements are not satisfied."
