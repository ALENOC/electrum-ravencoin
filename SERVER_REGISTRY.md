# Signed ElectrumX server registry

The wallet has two server-directory channels with intentionally different trust levels.

- `electrum/servers.json` is an unsigned discovery directory. Runtime updates from this file never grant `operatorGroup` trust.
- `electrum/servers.signed.json` is the Ed25519-authenticated registry. A valid signed registry may add, update, or remove servers and may assign or remove `operatorGroup` identities without rebuilding the wallet.

## Trust root

The client embeds only the public Ed25519 registry key. The current production trust root is:

- key ID: `d7a50f481a496f3e`
- raw public key: `f15e00d3e5edb0d9db31f81171a5e8716e247b53bc0e120655f665ba54b0d0c0`

The matching private key is **not part of the Git repository**. For the maintainer checkout it may be stored locally at `.server-registry-key/server-registry-ed25519-private.pem`; the whole `.server-registry-key/` directory is ignored by `.gitignore` and must never be force-added, committed, pushed, attached to issues, copied into CI/release artifacts, or placed in application data.

Recommended local permissions are `0700` on `.server-registry-key/` and `0600` on the private-key file. Keep a separate offline backup of the private key in a protected location. Losing or compromising the private key requires a client release that rotates the embedded public trust root.

The server-registry key is deliberately different from the Ravencoin Core safety-policy signing key. Compromise of one signing role must not automatically compromise the other.

## Availability and assurance model

One authenticated, individually validated `operatorGroup` is sufficient for normal Electrum wallet operation. This preserves the practical single-server model used by traditional Electrum clients.

When two or more trusted operator groups are available, the client compares their recent-chain evidence. Agreement provides stronger multi-operator assurance; disagreement fails closed and blocks sensitive chain-dependent actions. Discovery-only servers without authenticated `operatorGroup` metadata never count as trusted operators.

This means a sole trusted operator is an explicit trust assumption: compromise of that operator can still deceive a lightweight client that is not a full Ravencoin consensus verifier. The signed registry makes it possible to add independent operators later without recompiling already-released clients.

## Backend compatibility

Ravencoin Core has a hard safety floor of **4.8.0 or later**. Being numerically newer than 4.8.0 is necessary but not sufficient: each new Core release identity must also be certified by the separately signed Core safety policy before the wallet treats it as eligible.

The maintained RavenTag deployment currently uses **ElectrumX-RVN 1.13.x** as its known baseline. The client is intentionally not pinned to the exact `1.13.0` product-version string: later ElectrumX releases remain eligible when they negotiate the supported Electrum protocol and continue to provide the required Ravencoin backend capability contract. This avoids requiring a wallet rebuild merely because ElectrumX is upgraded to a compatible later release.

## Updating the registry

The currently committed registry is version **2**. Every future signed publication must use a strictly higher `registryVersion`; never reuse a version number for different contents.

1. Edit `electrum/servers.json` to the intended directory. `operatorGroup` should be present only on operators that have actually been reviewed and are intended to be trusted.
2. Choose the next strictly increasing registry version. For the next update after v2, use v3.
3. From the trusted signing checkout, confirm that `.server-registry-key/` is ignored by Git and that the private-key permissions remain restricted.
4. Sign the directory. The signer is intentionally standalone and requires only Python plus `cryptography`; it does not initialize the Electrum wallet/network stack.

```bash
git check-ignore -v .server-registry-key/server-registry-ed25519-private.pem

python3 contrib/sign_server_registry.py \
  --key .server-registry-key/server-registry-ed25519-private.pem \
  --registry-version 3 \
  --expires-days 365
```

5. Review both `electrum/servers.json` and `electrum/servers.signed.json`. Confirm the expected `registryVersion`, `keyId`, expiry, and server/operator assignments before committing.
6. Verify that `.server-registry-key/` does not appear in `git status` and never use `git add -f` on the private key.
7. Let the release-gating CI pass before publishing the registry change to `master`.

Already-built clients poll the signed registry and accept a newer registry only when the Ed25519 signature is valid, the document is not expired, and `registryVersion` is not below the highest version already accepted locally. A same-version document with different signed contents is rejected as equivocation.

## Failure behavior

If the signed registry cannot be downloaded, a still-valid cached signed registry remains active. If no valid signed registry exists, the client falls back to the compiled RavenTag anchor plus unsigned discovery data; unsigned data cannot create trusted operator groups.

If a signed registry expires while the client remains open, dynamic trust metadata is removed and the client returns to its compiled trusted-anchor fallback. The minimum trusted-operator threshold is local client policy and is not remotely configurable.
