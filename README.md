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

Seed generation, private-key handling, transaction signing and hardware-wallet
signing remain unchanged by this maintenance fork. Human-password wallet-file
encryption is strengthened to BIE3/scrypt with automatic migration from legacy
BIE1 after a successful unlock; BIE2 hardware-derived storage remains compatible.
This is a community-maintained fork, not a release by the Ravencoin Foundation or
the original Electrum maintainers.

## Why this maintained wallet exists

The August 2026 Ravencoin consensus incident showed why a wallet should not
trust a server's reported Core version by itself. The maintained wallet checks
the exact backend repository and commit against a signed, behaviourally
certified safe-Core policy, then validates the chain independently. The first
certified baseline is documented in the [server's incident and certification
guides](https://github.com/ALENOC/electrumx-ravencoin/tree/master/docs).

If this is your first time using the wallet, you can use an existing wallet
file and seed with the maintained fork. Existing wallet data and seed/signing
semantics remain compatible; a legacy BIE1 password-encrypted file is upgraded
to the BIE3/scrypt encryption envelope after a successful unlock.

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

The maintained release is **1.3.2**. Binaries are published on the
[releases page](https://github.com/ALENOC/electrum-ravencoin/releases) as a
source distribution, a Linux x86_64 AppImage, Windows executables from the
deterministic Wine build, and an x86_64 macOS DMG. Read
[RELEASE_NOTES_1.3.2.md](RELEASE_NOTES_1.3.2.md) before installing.

Verify what you download before running it: check the artifact against the
`SHA256SUMS` manifest, and check that manifest against the detached Ed25519
release signature, as described in [Release signing](RELEASE_SIGNING.md). An
artifact that fails either check is not a maintained release. Do not treat an
upstream Electrum binary as an ALENOC-certified release.

Running from source stays fully supported and is the reproducible path; see
[Building](docs/building.md).

## Quick start from source

```sh
git clone https://github.com/ALENOC/electrum-ravencoin.git
cd electrum-ravencoin
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
./contrib/install_btchip_python.sh
python -m pip install -e ".[full]"
./contrib/make_libsecp256k1.sh
./run_electrum --help
```

Two steps in that sequence are easy to miss:

* `contrib/install_btchip_python.sh` installs the Ledger legacy dependency
  `btchip-python`. Its published sdist declares an invalid PEP 440 requirement,
  so setuptools 66 and newer reject it and `pip install -e ".[full]"` aborts
  with `'extras_require' must be a dictionary whose values are strings or lists
  of strings containing valid project/version requirement specifiers`. The
  script downloads the sdist, verifies its sha256 digest, repairs the version
  string and installs it. Skip the step only if you install without the `full`
  extra, which leaves hardware wallet support out.
* `contrib/make_libsecp256k1.sh` builds the native `libsecp256k1` library into
  the `electrum/` directory. Without it, startup fails with
  `ImportError: Failed to load libsecp256k1`.

The wallet is started with `./run_electrum` from the source tree, or with the
`electrum_ravencoin` console script that the install places on `PATH`. There is
no `electrum.electrum_ravencoin` module to run with `python -m`.

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
  -> SAFE_CORE_VERIFIED (backend release claim accepted)
  -> independent chain validation passes (headers, checkpoint, nHeight)
  -> verified safe for use
```

`SAFE_CORE_VERIFIED` describes the backend's self-reported identity claim
against the signed policy; it is not remote-binary attestation, and by itself
it does not make a server usable. Chain validation is the independent leg,
and only a server that passes both is ever used. An unknown commit, wrong
repository, future release such as 4.9.0, stale or malformed evidence, wrong
network, chain conflict or failed checkpoint causes a fail-closed rejection at
whichever step it is caught.

This build's effective policy is always the baseline compiled into the
wallet; there is no runtime fetch of a remote policy yet, so a revocation
reaches users through a wallet update rather than a network channel. The
wallet never accepts an unknown newer Core as a fallback either way.

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
