# Security remediation — 2026-08-19

Baseline: `ab40dfcebbf5eccacbd6bfa2ac20b0b2cc440d61`

## RVN-SEC-001 — verified wallet state

Implementation review found that Ravencoin Core verifies KAWPOW with a
block-number-aware `progpow::verify(context, block_number, ...)`, while the
pinned Python binding does not expose that function. Calling its differently
shaped `kawpow_verify(context, ...)` would create a false security guarantee.

The independent-operator comparison machinery remains, but the wallet restores
the traditional Electrum availability model: one authenticated, individually
validated operator is sufficient for normal reads, SPV promotion, and broadcast.
If multiple trusted operator groups are online, their recent-chain windows must
agree and any conflict fails closed. Compromise of the sole trusted operator is
therefore an explicit residual risk; this client is not a full Ravencoin consensus
verifier. Unverified positive-height state remains quarantined until the serving
trusted interface passes authorization, and post-KAWPOW heights still cannot
downgrade to legacy hashing via timestamp manipulation.

## RVN-SEC-002 — backend claim semantics

`server.ravencoin_backend` is explicitly documented as an untrusted remote
capability claim. `POLICY_CONFORMING_BACKEND_CLAIM` is the canonical enum name;
`SAFE_CORE_VERIFIED` remains only as a backward-compatible alias.

## RVN-SEC-003 — TLS first contact

A failed CA validation no longer silently becomes first-contact TOFU. New
self-signed TLS endpoints require an explicit fingerprint. Existing pins and
CA-valid servers keep their prior behavior.

## RVN-SEC-004 — wallet password KDF

New human-password storage uses BIE3 with `hashlib.scrypt` (N=32768, r=8,
p=1), a random 16-byte per-wallet salt and the existing authenticated ECIES
payload. Legacy BIE1 remains readable and is atomically migrated to BIE3 after
a successful unlock. BIE2 hardware-derived storage remains compatible.

## Production operator anchor policy

`electrumx.raventag.com:50002` is the sole compiled server entry currently
trusted with an `operatorGroup` (`ALENOC`). Directory metadata does not bypass
live validation: the interface must still satisfy the TLS, Ravencoin backend,
Core safety-policy, chain-validation, and readiness gates before it can authorize
trusted chain-dependent actions.

RavenTag's maintained deployment baseline is Ravencoin Core **4.8.0 or later**
and ElectrumX-RVN **1.13.x**. Core releases newer than 4.8.0 are not trusted
merely because their version number is higher: the exact release identity must
also be accepted by the separately signed Core safety policy. ElectrumX is not
hard-pinned to the exact `1.13.0` product-version string; later compatible
ElectrumX-RVN releases may be used when they negotiate the supported Electrum
protocol and continue to provide the required Ravencoin backend capability
contract.

The `rvn4lyfe` clearnet/onion endpoints are discovery-only and deliberately do
not carry `operatorGroup`. Their presence or absence does not satisfy, weaken,
or raise the trusted-operator threshold. With the current policy, **one**
authenticated and individually validated trusted operator is sufficient for
normal wallet operation. If a future signed registry introduces a second
independently operated trusted group, agreement provides stronger assurance;
any disagreement between trusted groups still fails closed.

## Signed server registry

Security-sensitive server trust metadata is distributed through
`electrum/servers.signed.json`, authenticated by the dedicated Ed25519 registry
trust root. The current production key ID is `d7a50f481a496f3e`, and the
committed registry is version 2.

A valid signed registry may add, update, or remove servers and may assign or
remove `operatorGroup` values without requiring an already-released wallet to be
rebuilt. The registry path enforces signature verification, expiry, monotonic
`registryVersion`, local high-water rollback protection, and rejection of
same-version/different-content equivocation.

The signing private key is never tracked by Git. The maintainer checkout may keep
it in the gitignored `.server-registry-key/` directory for signing, with a
separate protected offline backup. Operational details are documented in
`SERVER_REGISTRY.md`.

## Dynamic server directory

Already-built clients can refresh the server directory at runtime through two
separate trust channels. The signed registry is authoritative for authenticated
operator metadata after all signature/expiry/rollback checks pass. The unsigned
`electrum/servers.json` channel is discovery-only: it may add, update, or remove
ordinary endpoints, but remote `operatorGroup` fields are stripped and cannot
mint trusted operators.

If no valid signed registry is available, the client retains the compiled
RavenTag trusted anchor and may use validated unsigned discovery data for other
endpoints. A still-valid cached signed registry is not downgraded merely because
a refresh temporarily fails.

## Regression coverage

`electrum/tests/test_security_remediation.py` covers the PoW downgrade guard,
read-chain authorization, verified-state quarantine, TLS first-contact policy,
backend-claim semantics, BIE3/scrypt migration and the RavenTag-only compiled
operator policy. `electrum/tests/test_server_list_updater.py` covers unsigned
trust stripping, RavenTag fallback behavior, signed-registry signature/tamper/
expiry/rollback/equivocation handling, the embedded registry key, and the
committed signed registry. `electrum/tests/test_write_authorization.py` and
`electrum/tests/test_recent_agreement_relay.py` cover the single-trusted-operator
availability model plus fail-closed conflicts when multiple trusted groups are
present. These tests are part of the release-gating CI surface.
