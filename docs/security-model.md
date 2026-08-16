# Security model

Documentation: [Home](../README.md) · [Docs index](README.md) ·
[Server policy](server-policy.md) · [Core certification](core-certification.md)

## Start with the simple idea

The wallet does not trust a server because it is reachable, popular, or because
it reports a high Core version. A future release can contain a new consensus
bug, and a remote server can misreport what binary it runs.

The protection is a chain of evidence:

```text
exact release identity
  -> behavioural certification
  -> signed policy
  -> fresh server evidence
  -> independent chain validation
```

This is why a hypothetical Core `4.9.0` is unreviewed until its exact
repository and commit are certified. It is also why a policy entry alone does
not make a third-party Electrum server trustworthy.

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

The Ed25519 policy signature authenticates the release list and profile
metadata. A policy is checked against the pinned public key, schema, expiry
and a persistent anti-rollback high-water mark before it is trusted, whether
it is loaded fresh or reloaded from the local cache; that floor is what stops
a validly signed but older document, cached or replayed, from undoing a
revocation. Revocation wins over a previous safe entry, and a remote policy
can never rehabilitate an identity the built-in baseline refuses.

This build does not fetch a policy over the network: the effective policy is
always the baseline compiled into the wallet
(`electrum/core_safety_baseline.json`). The verification, local cache and
anti-rollback state above exist and are exercised by the test suite, ready for
a future wallet update to ship a signed policy through them, but nothing in
this client calls out to fetch one today. In practice, **a revocation reaches
users only through a wallet update**, not a remote channel.

## What it does not prove

`server.ravencoin_backend` is self-reported backend evidence, not remote binary
attestation. A server can lie about its daemon. Independent headers, checkpoints,
network state and chain validation remain mandatory. Directory entries and
operator names are discovery hints, not trust proofs.

The wallet distinguishes three separate claims and never collapses them into
one: the server's identity claim (it says it runs a certified Core build), the
wallet's own chain validation (headers, checkpoint and nHeight checks against
that claim), and the combined result that actually decides whether the server
is used. A perfect identity claim from a hostile server whose chain fails
validation still never reaches the usable state; the connected-servers tooltip
labels each leg separately for the same reason.

## Independent chain validation: what it actually checks

Header validation confirms proof-of-work difficulty, chain linkage and, for
every KAWPOW-era header, that the header's declared height (`nheight`) matches
its real position in the chain. It does not recompute the KAWPOW/ProgPoW mix.

The wallet's KAWPOW check, like Ravencoin Core's own light-verification path
below its last checkpoint, accepts the mix hash carried in the header rather
than recomputing it from the memory-hard epoch dataset. Above the client's
last hardcoded checkpoint, Core itself recomputes the real mix; this wallet
does not. A malicious server can therefore fabricate a chain above the
checkpoint far more cheaply than honest KAWPOW mining, because it never has to
perform the memory-hard work the honest network does. Fork selection is still
cumulative-chainwork, so a fabricated chain would eventually need to sustain
more of that cheap work than the honest chain accumulates in the same time,
not just produce one block.

The checkpoint is the trust anchor this limitation depends on: it is a
hardcoded, wallet-shipped chain position below which a fabricated history is
already prohibitively expensive to construct (every 2016-block boundary would
have to be refabricated). It is not evidence that the chain above it is
correct; it is evidence that the chain cannot cheaply diverge below it. The
nHeight check narrows the forgery further by pinning the one field a full
verifier would use to select the KAWPOW epoch, but it does not replace
recomputing the mix.

Refreshing the checkpoint data itself requires generating a new,
spacing-aligned set of (hash, target) pairs from a fully synchronized,
independently verified Ravencoin Core node (`contrib/checkpoint_generator.py`)
covering every 2016-block boundary from the current last checkpoint forward.
That data-generation work was not performed in this remediation pass: no
trusted, fully synced node was available in this environment to produce and
independently cross-check several hundred boundary entries, and fabricating
that data from a single untrusted source (including the wallet's own
candidate servers) would be exactly the mistake this document warns against.
The residual assumption in the meantime is: checkpoint (currently height
3,455,423) + exact nHeight validation + chain-continuity/difficulty checks +
the signed backend-identity policy together bound what a hostile server can
cheaply fabricate above the checkpoint, but full memory-hard KAWPOW
verification above it is not performed by this wallet. This is a known,
documented limitation, not a silent gap.

## Wallet boundary

Seed generation, key derivation, wallet encryption, wallet files, transaction
construction/signing and hardware-wallet behavior were not changed by this fork.
