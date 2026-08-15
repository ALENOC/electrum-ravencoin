# Electrum Ravencoin — maintained for safe Core 4.8+ servers

This is the maintained ALENOC fork of
[`Electrum-RVN-SIG/electrum-ravencoin`](https://github.com/Electrum-RVN-SIG/electrum-ravencoin),
updated for modern Ravencoin operation after the August 2026 consensus incident.
It is not an official Ravencoin or Electrum release. Original copyright, MIT
licensing, history, and upstream attribution are preserved.

## Security status

Normal mainnet operation accepts an ElectrumX endpoint only when all of these are
true:

- `server.ravencoin_backend` is present, current, and structurally valid;
- the backend is Ravencoin Core **4.8.0 or newer** (exactly 4.8.0 is accepted);
- the backend reports mainnet, matching network evidence, synchronized heights,
  the 4,487,775 checkpoint, and post-KAWPOW height validation;
- the version text, numeric Core version, and Core subversion agree; and
- normal genesis, checkpoint, header-continuity, and chain validation also pass.

Core 4.6.x and 4.7.x, wrong-network servers, unsafe flags, stale/malformed
responses, timeouts, and `method not found` are rejected. Legacy or unverifiable
servers are intentionally ineligible; this is a security feature, not a
connectivity bug. If every safe endpoint disappears, the wallet remains
degraded/offline instead of falling back to an unsafe server.

Backend self-report is necessary but not sufficient. A server that lies about
its backend still has to supply a chain that passes the client's independent
header checks. An interface does not enter the usable mainnet pool until both
gates succeed:

```
Electrum TCP/TLS
       |
       v
server.ravencoin_backend ---- fail ----> reject
       |
       | Core >= 4.8.0, mainnet, safety flags
       v
header / checkpoint / chain ---- fail -> quarantine
       |
       v
eligible mainnet interface
```

## Three different versions

These identities are never interchangeable:

1. **Electrum client version** — this wallet application.
2. **ElectrumX server version** — returned by `server.version` and
   `serverVersion`.
3. **Ravencoin Core backend version** — returned only by the validated
   `backend.version` and `backend.versionNumber` fields of
   `server.ravencoin_backend`.

For example, `server.version = "4.8.0"` with backend Core 4.7.0 is rejected.
Operator identity and ALENOC branding are not proof of eligibility: any
third-party operator can implement the same capability and pass the same chain
policy without vendor lock-in.

## Diagnostics

The connected-node tooltip shows the Electrum host, ElectrumX version, backend
Core version/subversion/network/heights, backend safety state, and chain
validation state. Rejection messages distinguish an old Core, an unverifiable
backend, wrong network, malformed evidence, timeout, unsafe flags, and chain
conflict. Responses are never logged verbatim.

The bundled historical server names remain discovery candidates, not a claim of
safety. Each connection must pass the live capability and chain gates before it
enters the selection pool. No new endpoint is fabricated or trusted by hostname.

## Cryptography scope

This maintenance changes network eligibility and diagnostics only. Wallet file
format, seed generation/derivation, private-key storage, wallet encryption,
transaction signing, hardware-wallet signing, asset signing, and unrelated NFC
cryptography are unchanged. No new wallet binary release is implied by this
branch.

## Run a compatible server

The coordinated maintained server, including the default pinned Core 4.8.0 +
ElectrumX deployment, is at
[`ALENOC/electrumx-ravencoin`](https://github.com/ALENOC/electrumx-ravencoin).

Neil Booth and the Electrum developers created the original Electrum software;
the Electrum-RVN-SIG community performed the Ravencoin conversion and asset
work. ALENOC maintains this fork and does not claim original authorship.

## Getting started

Electrum itself is pure Python, and so are most of the required dependencies,
but not everything. The following sections describe how to run from source, but here
is a TL;DR:

```
$ sudo apt-get install libsecp256k1-dev
$ python3 -m pip install --user ".[gui,crypto]"
```

### Not pure-python dependencies

If you want to use the Qt interface, install the Qt dependencies:
```
$ sudo apt-get install python3-pyqt5
```

For elliptic curve operations,
[libsecp256k1](https://github.com/bitcoin-core/secp256k1)
is a required dependency:
```
$ sudo apt-get install libsecp256k1-dev
```

Alternatively, when running from a cloned repository, a script is provided to build
libsecp256k1 yourself:
```
$ sudo apt-get install automake libtool
$ ./contrib/make_libsecp256k1.sh
```

Due to the need for fast symmetric ciphers,
[cryptography](https://github.com/pyca/cryptography) is required.
Install from your package manager (or from pip):
```
$ sudo apt-get install python3-cryptography
```

If you would like hardware wallet support,
[see this](https://github.com/spesmilo/electrum-docs/blob/master/hardware-linux.rst).


### Running from tar.gz

If you downloaded a reviewed source package (tar.gz), you can run
Electrum from its root directory without installing it on your
system; all the pure python dependencies are included in the 'packages'
directory. To run Electrum from its root directory, just do:
```
$ ./run_electrum
```

You can also install Electrum on your system, by running this command:
```
$ sudo apt-get install python3-setuptools python3-pip
$ python3 -m pip install --user .
```

This will download and install the Python dependencies used by
Electrum instead of using the 'packages' directory.
It will also place an executable named `electrum` in `~/.local/bin`,
so make sure that is on your `PATH` variable.


### Development version (git clone)

_(For OS-specific instructions, see [here for Windows](contrib/build-wine/README_windows.md),
and [for macOS](contrib/osx/README_macos.md))_

Check out this maintained branch from GitHub:
```
$ git clone --branch maintenance/server-compat https://github.com/ALENOC/electrum-ravencoin.git
$ cd electrum-ravencoin
$ git submodule update --init
```

Run install (this should install dependencies):
```
$ python3 -m pip install --user -e .
```

Create translations (optional):
```
$ sudo apt-get install python3-requests gettext qttools5-dev-tools
$ ./contrib/pull_locale
```

Finally, to start Electrum:
```
$ ./run_electrum
```

### Run tests

Run unit tests with `pytest`:
```
$ pytest electrum/tests -v
```

To run a single file, specify it directly like this:
```
$ pytest electrum/tests/test_bitcoin.py -v
```

## Creating Binaries

- [Linux (tarball)](contrib/build-linux/sdist/README.md)
- [Linux (AppImage)](contrib/build-linux/appimage/README.md)
- [macOS](contrib/osx/README.md)
- [Windows](contrib/build-wine/README.md)
- [Android](contrib/android/Readme.md)


## Contributing

Any help testing the software, reporting or fixing bugs, reviewing pull requests
and recent changes, writing tests, or helping with outstanding issues is very welcome.
Implementing new features, or improving/refactoring the codebase, is of course
also welcome, but to avoid wasted effort, especially for larger changes,
we encourage discussing these on the issue tracker or IRC first.

Besides [GitHub](https://github.com/spesmilo/electrum),
most communication about Electrum development happens on IRC, in the
`#electrum` channel on Libera Chat. The easiest way to participate on IRC is
with the web client, [web.libera.chat](https://web.libera.chat/#electrum).
