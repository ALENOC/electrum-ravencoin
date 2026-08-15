# Copyright (c) 2026, the Electrum-Ravencoin community maintainers
#
# The MIT License (MIT).  See LICENCE for details.

"""Parse optional, self-reported Ravencoin Core backend evidence.

Maintained ElectrumX-RVN servers expose ``server.ravencoin_backend`` so operators and
clients can distinguish the ElectrumX software version from the daemon behind it.  This
is useful diagnostic evidence only: clients must still verify headers and chain history.
"""

from dataclasses import dataclass
import re
from typing import Any, Mapping, Optional


MINIMUM_SAFE_CORE_NUMBER = 4_080_000
_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?$")


@dataclass(frozen=True)
class RavencoinBackendEvidence:
    server_name: str
    server_version: str
    core_version: str
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
        """Whether the server's claim is internally compatible with the 4.8 floor.

        The name deliberately says *reports*.  This value is not chain proof and must not
        replace SPV header validation or independent server comparison.
        """
        return (
            self.core_version_number >= MINIMUM_SAFE_CORE_NUMBER
            and self.network == "main"
            and self.server_reports_core_safe
            and self.server_reports_network_match
            and self.server_reports_checkpoint_4487775
        )


def _integer(value: Any, field: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError("invalid {}".format(field))
    return value


def _boolean(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError("invalid {}".format(field))
    return value


def _string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("invalid {}".format(field))
    return value


def parse_ravencoin_backend_evidence(response: Any) -> RavencoinBackendEvidence:
    """Validate the sanitized optional response without trusting its assertions."""
    if not isinstance(response, Mapping):
        raise ValueError("backend evidence must be an object")
    backend = response.get("backend")
    compatibility = response.get("compatibility")
    if not isinstance(backend, Mapping) or not isinstance(compatibility, Mapping):
        raise ValueError("backend evidence is missing nested objects")

    core_version = _string(backend.get("version"), "backend.version")
    minimum_safe_core = _string(
        compatibility.get("minimumSafeCore"), "compatibility.minimumSafeCore"
    )
    if not _VERSION_RE.fullmatch(core_version) or not _VERSION_RE.fullmatch(minimum_safe_core):
        raise ValueError("malformed Core version")

    blocks = _integer(backend.get("blocks"), "backend.blocks")
    headers = _integer(backend.get("headers"), "backend.headers")
    if headers < blocks:
        raise ValueError("backend headers are below blocks")
    ibd = backend.get("initialBlockDownload")
    if ibd not in (True, False, None):
        raise ValueError("invalid backend.initialBlockDownload")

    return RavencoinBackendEvidence(
        server_name=_string(response.get("server"), "server"),
        server_version=_string(response.get("serverVersion"), "serverVersion"),
        core_version=core_version,
        core_version_number=_integer(backend.get("versionNumber"), "backend.versionNumber"),
        core_subversion=_string(backend.get("subversion"), "backend.subversion"),
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
