# Electrum Ravencoin

The maintained ALENOC wallet fork for Ravencoin. It keeps the upstream wallet
and signing model while requiring stronger evidence from mainnet Electrum
servers.

> **Security notice:** a server is eligible only when its backend Core release
> identity is present in the signed safe-Core policy and all freshness, network,
> synchronization and independent chain checks pass. A version number alone is
> never trust. The initial certified identity is
> `2miners/Ravencoin` `v4.8.0` at commit
> `b60f50e04f1fba425b28804e61be2694faaf3469`.

This is not an official Ravencoin or Electrum release. Wallet files, seed
generation, private-key handling, transaction signing, hardware-wallet support
and wallet cryptography remain unchanged by this maintenance fork.

## Documentation

| Guide | Purpose |
|---|---|
| [Documentation index](docs/README.md) | Full guide map |
| [Security model](docs/security-model.md) | Trust boundaries and fail-closed behavior |
| [Server policy](docs/server-policy.md) | Backend evidence and rejection states |
| [Core certification](docs/core-certification.md) | Certified releases and signed policy |
| [Troubleshooting](docs/troubleshooting.md) | Common connection and policy failures |
| [Building](docs/building.md) | Source builds and packaging |
| [Releases](docs/releases.md) | Maintained release policy |
| [Upstream and credits](docs/upstream-and-credits.md) | Lineage, MIT license and attribution |

## Download

No maintained ALENOC binary release is being published yet. Run from source
after reviewing the current release notes, or build a local package using
[Building](docs/building.md). Do not treat an upstream Electrum binary as an
ALENOC-certified release.

## Quick start from source

```sh
git clone https://github.com/ALENOC/electrum-ravencoin.git
cd electrum-ravencoin
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[full]"
python -m electrum.electrum_ravencoin --help
```

The exact optional extras vary by platform. See [Building](docs/building.md)
for native dependencies and GUI/hardware options.

## Why a server can be rejected

The wallet distinguishes three identities: the wallet application,
`server.version` for ElectrumX, and `server.ravencoin_backend` for the Core
backend. The last one must identify a release present in the signed policy.

```text
server reachable
  -> backend evidence present and fresh
  -> exact repository + commit is policy-certified
  -> network/sync/checkpoint flags pass
  -> independent chain validation passes
  -> SAFE_CORE_VERIFIED
```

An unknown commit, wrong repository, future release such as 4.9.0, stale or
malformed evidence, wrong network, chain conflict or failed checkpoint causes a
fail-closed rejection. If policy distribution is unavailable, the wallet uses
the last verified cache or built-in baseline; it never accepts an unknown newer
Core as a fallback.

The current release certification is complete, but live deployment validation is
still in progress. A certified software identity does not cryptographically
attest to which binary a third-party Electrum server is running.

## Server operators

Run the maintained server from
[ALENOC/electrumx-ravencoin](https://github.com/ALENOC/electrumx-ravencoin).
Operators should read its [Getting started guide](https://github.com/ALENOC/electrumx-ravencoin/blob/master/docs/getting-started.md)
and complete its live validation checklist before publishing an endpoint.

## License and credits

This repository remains MIT-licensed. Electrum created the original wallet;
the Electrum-RVN-SIG community performed the Ravencoin adaptation and asset
work; ALENOC maintains this fork. Original notices and historical authors are
preserved. See [NOTICE.md](NOTICE.md), [LICENCE](LICENCE), [AUTHORS](AUTHORS),
and [Upstream and credits](docs/upstream-and-credits.md).
