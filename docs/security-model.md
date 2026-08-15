# Security model

Documentation: [Home](../README.md) · [Docs index](README.md) ·
[Server policy](server-policy.md) · [Core certification](core-certification.md)

## What changed

Mainnet server selection now requires this chain of evidence:

```text
exact repository + exact commit
  -> behavioural Core certification
  -> signed safe-Core policy
  -> fresh backend evidence
  -> independent chain validation
```

The historical 4.8.0 threshold is context, not automatic trust. Older Core
versions are known unsuitable, but a future 4.9.0 or any other unlisted release is
also unreviewed until its exact identity is certified and signed into policy.

## What the policy protects

The Ed25519 policy signature authenticates the release list and profile metadata.
Policy updates are checked against the pinned public key, expiry and a persistent
anti-rollback high-water mark. Revocation wins over a previous safe entry.

Precedence is: valid newer signed policy, high-water mark, revocation rules,
last-known-valid cache, then built-in baseline. Policy-host downtime never
creates trust in an unknown release.

## What it does not prove

`server.ravencoin_backend` is self-reported backend evidence, not remote binary
attestation. A server can lie about its daemon. Independent headers, checkpoints,
network state and chain validation remain mandatory. Directory entries and
operator names are discovery hints, not trust proofs.

## Wallet boundary

Seed generation, key derivation, wallet encryption, wallet files, transaction
construction/signing and hardware-wallet behavior were not changed by this fork.
