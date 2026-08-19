# Security remediation — 2026-08-19

Baseline: `ab40dfcebbf5eccacbd6bfa2ac20b0b2cc440d61`

## RVN-SEC-001 — verified wallet state

Implementation review found that Ravencoin Core verifies KAWPOW with a
block-number-aware `progpow::verify(context, block_number, ...)`, while the
pinned Python binding does not expose that function. Calling its differently
shaped `kawpow_verify(context, ...)` would create a false security guarantee.

The single-malicious-ElectrumX path is closed instead by extending the existing
independent-operator chain-consensus boundary from transaction broadcast to
promotion of remote data into verified wallet state. The exact serving
interface must match the agreed chain, the claimed height must be no newer than
the agreed witness tip, authorization is rechecked after the proof request,
and unverified positive-height outputs/spends are quarantined from balances and
coin selection. Existing post-checkpoint verification caches are demoted once
and revalidated. Post-KAWPOW heights also cannot downgrade to legacy hashing by
supplying an old timestamp.

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

`electrumx.raventag.com:50002` is the only compiled server entry currently
trusted with an `operatorGroup` (`ALENOC`). It is operator-controlled and is
expected to run Ravencoin Core 4.8.0 with ElectrumX 1.13; the live backend and
chain gates remain authoritative and directory metadata alone never authorizes
it.

The `rvn4lyfe` clearnet/onion endpoints are discovery-only and deliberately do
not carry `operatorGroup`. Consequently the two-independent-operator quorum is
currently unavailable in the shipped directory: sensitive writes and promotion
of remote data into verified wallet state fail closed until a second independently
trusted operator anchor (or a cryptographically signed server registry) is added.
This is an intentional safety-over-availability choice.

## Dynamic server directory

Already-built clients can refresh ordinary ElectrumX discovery entries from the
repository at runtime. The unsigned remote list may add, update, or remove
non-anchor servers, but it cannot replace the RavenTag anchor and any remote
`operatorGroup` field is discarded. A validated cache is used as fallback, with
the compiled directory remaining the startup fallback when no cache exists.

## Regression coverage

`electrum/tests/test_security_remediation.py` covers the PoW downgrade guard,
read-chain authorization, verified-state quarantine, TLS first-contact policy,
backend-claim semantics, BIE3/scrypt migration and the RavenTag-only production
operator policy. `electrum/tests/test_server_list_updater.py` covers the runtime
directory update trust boundary, validation, cache integrity and anchor
immutability. Both are part of the release-gating CI test surface.
