# Signed ElectrumX server registry

The wallet has two server-directory channels with intentionally different trust levels.

- `electrum/servers.json` is an unsigned discovery directory. Runtime updates from this file never grant `operatorGroup` trust.
- `electrum/servers.signed.json` is the Ed25519-authenticated registry. A valid signed registry may add, update, or remove servers and may assign or remove `operatorGroup` identities without rebuilding the wallet.

## Trust root

The client embeds only the public Ed25519 registry key. The current key ID is:

`a81ee9b1b61a5dcf`

The private key must remain outside the repository, CI, release artifacts, cloud drives, issue attachments, and application data directories. Losing or compromising this private key requires a client release that rotates the embedded public trust root.

The server-registry key is deliberately different from the Ravencoin Core safety-policy signing key. Compromise of one signing role must not automatically compromise the other.

## Updating the registry

1. Edit `electrum/servers.json` to the intended directory. `operatorGroup` should be present only on operators that have actually been reviewed and are intended to count toward independent quorum.
2. Increment `registryVersion`. Never reuse an old version number for different contents.
3. From a trusted/offline machine, sign the directory with:

```bash
python3 contrib/sign_server_registry.py \
  --key /secure/offline/server-registry-ed25519-private.pem \
  --registry-version 2 \
  --expires-days 180
```

4. Review both `electrum/servers.json` and `electrum/servers.signed.json` before committing.
5. Let CI pass before publishing the change to `master`.

Already-built clients poll the signed registry and accept a newer registry only when the Ed25519 signature is valid, the document is not expired, and `registryVersion` is not below the highest version already accepted locally.

## Failure behavior

If the signed registry cannot be downloaded, a still-valid cached signed registry remains active. If no valid signed registry exists, the client falls back to the compiled RavenTag anchor plus unsigned discovery data; unsigned data cannot create trusted operator groups.

If a signed registry expires while the client remains open, dynamic trust metadata is removed and the client returns to the fail-closed fallback. The quorum threshold itself is not remotely configurable.
