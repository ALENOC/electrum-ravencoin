# Electrum Ravencoin: maintained wallet for Ravencoin Core 4.8+ infrastructure

## New to Ravencoin? Read this first

If you already know what an ElectrumX server is, skip to the
[security notice](#security-notice-in-one-paragraph). If not, five short
paragraphs will save you a lot of confusion later.

**Ravencoin** is a public network that keeps a shared record of who owns what.
Every transaction ever made lives in that record, called the blockchain. It works
because thousands of independent computers each keep a full copy and check each
other, so no single one of them can rewrite history or invent coins.

**A Ravencoin node** is one of those computers, running a program called
Ravencoin Core. It downloads the entire history, verifies every block against the
rules, and rejects anything invalid. It asks nobody for permission and trusts
nobody's word.

**This wallet is not a node.** Your phone or laptop cannot store and verify tens
of gigabytes of history, and you would not want it to. So the wallet keeps your
keys, and asks somebody else the question "what is my balance, and has anyone paid
me?"

**The somebody else is an ElectrumX server.** It sits next to a Ravencoin node,
reads the whole chain once, and builds an index from addresses to transactions.
Then it can answer your wallet in milliseconds. Your keys never leave your device:
the server sees the addresses you ask about, never your seed phrase, and it cannot
move your coins.

**That is why this wallet cares so much which server it talks to.** A server you
depend on for the truth is a server that can try to tell you the wrong truth, for
example hiding a payment or showing a chain that does not exist. This fork
therefore checks the server's own claims, checks the chain it serves, and refuses
servers that cannot prove they are running a safe, patched Ravencoin node behind
them. When you see this wallet reject a server, that is the feature working.

```
your wallet                  an ElectrumX server              a Ravencoin node
your keys, your seed  <--->  index of the whole chain  <--->  full verified history
never shared                 sees addresses only              checks every block
```

### You can help, and it is easier than it sounds

There are thousands of Ravencoin nodes but only a handful of public ElectrumX
servers, and almost every light wallet leans on that handful. That is bad for
privacy, because few operators see a lot of wallet traffic, and bad for
reliability, because those few machines are a single point of failure for the
whole light-wallet ecosystem.

If you support Ravencoin and own a small always-on computer, running a server is
probably the most useful non-programming contribution available to you. A
Raspberry Pi 5 with 8 GB of RAM and an SSD is enough. The server holds no coins,
needs no keys, and can serve just your own wallets if you prefer. The maintained
server, with a step-by-step guide written for people who have never done this, is
at [`ALENOC/electrumx-ravencoin`](https://github.com/ALENOC/electrumx-ravencoin).

Every extra independent server makes every wallet in the network a little harder
to lie to, including yours.

This is the maintained ALENOC fork of
[`Electrum-RVN-SIG/electrum-ravencoin`](https://github.com/Electrum-RVN-SIG/electrum-ravencoin),
updated for the Ravencoin network as it exists after the August 2026 consensus
incident. It is not an official Ravencoin or Electrum release. Original
copyright, MIT licensing, repository history and upstream attribution are
preserved, and ALENOC does not claim authorship of the original wallet.

## Security notice, in one paragraph

On mainnet this wallet only uses an Electrum server after the server proves that
the Ravencoin Core node behind it is version **4.8.0 or newer**, and after the
wallet independently validates the chain that server serves. A server that
cannot prove its backend is refused, even if it is otherwise reachable and
responsive. If no server can prove it, the wallet stays disconnected rather than
using an unverifiable one. That is deliberate: it is a safety property, not a
connectivity bug.

Your keys are unaffected by any of this. Seed generation, key handling, wallet
encryption, the wallet file format and transaction signing are untouched by this
maintenance work. See [Security model](#security-model).

## Why this maintained fork exists

In August 2026 a Ravencoin consensus problem involving post-KAWPOW header height
validation forced the network onto a patched Ravencoin Core generation. The
Electrum server ecosystem had to move to Ravencoin Core 4.8.0 or newer, and a
wallet has no way to tell a patched backend from an unpatched one by looking at
the Electrum server's own version string.

So this fork asks the server directly, in a way the server has to answer with
checkable evidence, and it refuses infrastructure that cannot demonstrate the
modern safety baseline. Everything else about the wallet stays as upstream built
it.

Primary reference for the patched Core generation: the
[2miners Ravencoin 4.8.0 release](https://github.com/2miners/Ravencoin/releases/tag/v4.8.0).

## Three different versions, never interchangeable

This trips up almost everyone, so it is worth being explicit. Three independent
version numbers are involved:

| Version | What it identifies | Where it comes from |
|---|---|---|
| Electrum client version | this wallet application | the wallet itself |
| ElectrumX server version | the Electrum server software | `server.version` |
| Ravencoin Core backend version | the full node behind that server | `server.ravencoin_backend` |

`server.version` identifies the ElectrumX software, for example
`ElectrumX-RVN 1.13.0.dev1`. It says nothing at all about the Ravencoin Core
node behind it, and ElectrumX is not itself "version 4.8.0".

```
Electrum wallet
       |
       v
ElectrumX server
       |
       |-- server.version            -> ElectrumX software identity
       |
       |-- server.ravencoin_backend  -> Ravencoin Core backend evidence
       |
       v
   backend Core >= 4.8.0 ?
       |
     YES -> continue validating
      NO -> reject the server
```

A server reporting `server.version = "4.8.0"` while its backend is Core 4.7.0 is
rejected. The wallet reads the Core version only from the validated
`backend.version` and `backend.versionNumber` fields.

## Ravencoin Core compatibility policy

**A newer version number does not mean a safer one.** This wallet does not ask
"is the backend at least 4.8.0?". It asks "is this exact build one that has been
certified against the safety profile I require?".

The identity that matters is the **source repository plus the exact commit**. A
version string is metadata: two repositories can publish the same version number
from entirely different code, and a release that has not been tested proves
nothing about itself.

| Backend Ravencoin Core | Result | Why |
|---|---|---|
| 4.6.1, 4.6.1.1, 4.7.0 | rejected | known unsafe, predates the incident fix |
| 4.8.0 from the certified commit | accepted | certified against the current profile |
| 4.8.0 from another commit or repository | rejected | different build, not the certified one |
| a future 4.8.1, 4.9.0, 5.0.0 | rejected until certified | nobody has tested it yet |
| a certified release later revoked | rejected | revocation is respected immediately |

The certified baseline shipped with this wallet is
`2miners/Ravencoin` `v4.8.0` at commit `b60f50e04f1fba425b28804e61be2694faaf3469`.

When a new Ravencoin Core release appears, it is discovered automatically from
the two upstream sources, built at its exact commit, and put through a
behavioural certification suite. Only if it passes does it enter a signed policy
update that wallets can accept. Until then this wallet refuses it, and shows
`CORE_UNREVIEWED_VERSION` rather than pretending the release is fine.

That refusal is the intended behaviour. A wallet that trusted every new release
on sight would have trusted the release that caused the August 2026 incident.

Accepted here still means only "passed the release-identity check". Network,
synchronization, safety flags and independent chain validation all still apply.

## How server validation works

Evidence is requested immediately after the protocol handshake, and the server
is dropped as soon as any gate fails.

```
Electrum server reachable
        |
        v
server.ravencoin_backend present and well formed?
        |-- NO  -> reject
        v YES
backend Core >= 4.8.0?
        |-- NO  -> reject
        v YES
mainnet, synchronized, safety flags all true, evidence fresh?
        |-- NO  -> reject
        v YES
independent chain validation (genesis, checkpoints, header continuity)
        |-- FAIL -> quarantine, never enters the server pool
        v PASS
SAFE_CORE_VERIFIED, server eligible
```

### Fail-closed table

For normal mainnet use:

| Condition | Result |
|---|---|
| `server.ravencoin_backend` missing from the response | rejected |
| `method not found` for that call | rejected, `BACKEND_METHOD_UNAVAILABLE` |
| request times out or connection drops | rejected, `UNREACHABLE`, retried on reconnect |
| malformed or unparsable evidence | rejected, `BACKEND_MALFORMED` |
| Core version unreadable or not a version | rejected, `CORE_VERSION_UNKNOWN` |
| Core below 4.8.0 | rejected, `CORE_TOO_OLD` |
| version text, numeric version and subversion disagree | rejected, `BACKEND_MALFORMED` |
| backend on the wrong network | rejected, `WRONG_NETWORK` |
| `coreSafe` false | rejected, `BACKEND_UNSAFE` |
| `backendSynchronized` false, or blocks and headers disagree | rejected, `BACKEND_UNSAFE` |
| `initialBlockDownload` true | rejected, `BACKEND_UNSAFE` |
| `checkpoint4487775` false | rejected, `BACKEND_UNSAFE` |
| `kawpowHeightValidation` false | rejected, `BACKEND_UNSAFE` |
| evidence older than 5 minutes, or timestamped in the future | rejected, `BACKEND_UNSAFE` |
| chain history conflicts with expected Ravencoin history | quarantined, `CHAIN_CONFLICT` |

Availability is intentionally sacrificed here. An unverifiable server is exactly
the case where a wallet is most likely to be shown a wrong chain, so connecting
anyway would trade a visible inconvenience for an invisible risk.

Off mainnet, on testnet or regtest, the capability is optional, because those
networks are for development and the safety baseline is a mainnet property.

## Backend self-report is necessary but not sufficient

A server does not become trusted by claiming "I use Core 4.8.0". The claim only
gets it past the first gate. The wallet then validates the genesis hash,
checkpoints and header continuity of the chain the server actually serves, and a
server whose chain conflicts is quarantined even when its self-report looked
perfect. Chain validation happens before the server is marked ready, so a
conflicting server never enters the pool the wallet selects from.

## What `server.ravencoin_backend` returns

The capability exists so a wallet can make a safety decision from checkable
evidence rather than from a hostname or a brand. The response carries no
credentials, no wallet data and no file paths. Fields, as implemented by the
maintained server:

| Field | Meaning |
|---|---|
| `server`, `serverVersion` | ElectrumX identity and software version |
| `backend.name` | must be `Ravencoin Core` |
| `backend.version`, `backend.versionNumber` | backend Core version, text and numeric, for example `4.8.0` and `4080000` |
| `backend.subversion` | the daemon's own string, for example `/Ravencoin:4.8.0/` |
| `backend.network` | `main`, `test` or `regtest` |
| `backend.blocks`, `backend.headers` | backend chain position |
| `backend.initialBlockDownload` | whether the backend is still in initial download |
| `compatibility.minimumSafeCore` | the server's declared floor, expected `4.8.0` |
| `compatibility.coreSafe` | version, network and checkpoint policy all hold |
| `compatibility.networkMatches` | the daemon's network matches the server's |
| `compatibility.backendSynchronized` | the backend is caught up |
| `compatibility.kawpowHeightValidation` | the server enforces the post-KAWPOW height rule |
| `compatibility.checkpoint4487775` | the incident checkpoint was **verified**, see below |
| `observedAt` | when the server collected this evidence |

### Checkpoint semantics

Two different statements are kept apart, and only the second is published:

- **known or configured**: the server knows the checkpoint at height 4,487,775.
  A backend that has not yet reached that height cannot contradict it, so the
  server is allowed to keep running and syncing.
- **verified**: the server actually asked its backend for the block hash at
  height 4,487,775 and it matched.

`compatibility.checkpoint4487775` reports verification, not configuration. It is
therefore `false` on a server whose backend is still syncing, alongside
`backendSynchronized: false`, and becomes `true` only once the comparison has
really been made. This wallet requires the verified form, so a still-syncing
server is not eligible yet. A server must never advertise a check it has not
performed.

## How a Core release becomes trusted

```
2miners/Ravencoin ---+
                     |
                     +--> release watcher --> build the exact commit
                     |                              |
RavenProject/Ravencoin ---+                         v
                                          behavioural certification
                                                    |
                                            pass? --+-- no --> refused, review required
                                                    |
                                                   yes
                                                    v
                                        signed safe-Core policy update
                                                    |
                                                    v
                                    wallets accept the new release identity
```

Publishing a GitHub release grants nothing. Both upstream sources are treated
identically: being the historical home of the project does not make a release
trusted, and neither does being the source of the current certified build.

The wallet ships with a built-in baseline so it works with no network access to
any policy service. A signed policy update can **add** newly certified releases
and can **revoke** anything, including the baseline entry. It can never do the
reverse: a remote policy cannot rehabilitate a release the built-in baseline
refuses, and it cannot introduce a new signing key. Policy updates are also
protected against rollback, so an attacker cannot replay an old signed policy to
undo a revocation.

If the policy service is unreachable, the wallet keeps using the last policy it
verified, or the built-in baseline. It never falls back to accepting an
uncertified release.

## Server eligibility states

These are the state names used internally and surfaced in diagnostics:

| State | Plain meaning |
|---|---|
| `SAFE_CORE_VERIFIED` | backend proved Core 4.8.0+, all flags fine, chain validated. Usable. |
| `CORE_TOO_OLD` | the backend is real but older than 4.8.0. |
| `CORE_VERSION_UNKNOWN` | no usable Core version could be established. |
| `BACKEND_METHOD_UNAVAILABLE` | the server does not implement `server.ravencoin_backend`. |
| `BACKEND_MALFORMED` | the response was invalid, inconsistent or self-contradictory. |
| `WRONG_NETWORK` | the backend is not proving Ravencoin mainnet. |
| `BACKEND_UNSAFE` | structurally valid evidence that fails a safety requirement. |
| `CHAIN_CONFLICT` | the served chain conflicts with expected Ravencoin history. |
| `UNREACHABLE` | no answer: timeout, disconnect or transport failure. |

## If no safe server is available

```
no eligible server
        |
        v
wallet stays degraded or disconnected
        |
        v
waits for infrastructure that can prove a safe backend
```

The wallet does not fall back to a legacy or unverifiable server to appear
online. Balances and history simply do not refresh until a server qualifies.
This is the intended behaviour, and the diagnostics explain which requirement
each candidate failed.

## Any operator can qualify

There is no vendor lock-in and no allowlist. Eligibility comes from protocol
evidence plus chain validation, so a server run by ALENOC, 2Miners,
Electrum-RVN SIG, RavenMiner, or any independent community operator is treated
identically: implement `server.ravencoin_backend`, run a Core 4.8.0+ backend,
serve the real chain, and the server qualifies. Operator identity, branding and
hostname are not trust proofs and are never used as one.

### Where candidate servers come from

Three sources, all treated the same way:

1. the small **built-in seed list** that ships with the wallet;
2. a **signed server directory** published by the monitoring project, which is a
   discovery hint about which endpoints currently exist and look healthy;
3. **peer discovery**, where servers name other servers.

All three produce candidates. None of them produces trust:

```
seeds + signed directory + peer gossip
                 |
                 v
        candidate endpoints
                 |
                 v
   this wallet verifies each one itself
   server.version, server.ravencoin_backend,
   certified-release policy, chain validation
                 |
                 v
          eligible servers
```

A directory entry labelled SAFE is somebody else's past opinion about a server
you are about to talk to directly. The wallet re-checks everything anyway, so a
compromised or stale directory can waste a connection attempt but cannot make an
unsafe server acceptable. Directory snapshots are signed, versioned and
expiring, which stops an old one being replayed, and the wallet keeps its
built-in seeds so it never depends on any single service being online.

If the directory is unreachable, the wallet uses seeds and whatever it already
knows. It does not lower its standards to find something to connect to.

### Bundled server list

The bundled list is a discovery hint inherited from upstream, not a safety
claim. Its entries are historical and unverified under the current policy, and
each one has to pass the live capability and chain gates on every connection
like any other candidate. No endpoint is trusted because it appears in that
file, and no replacement endpoints have been invented here.

Expect the pool of qualifying public servers to be small at first: the
capability requirement is deliberately strict, so servers that have not upgraded
are excluded by design. This document intentionally does not list live
hostnames, since that list changes as operators come and go.

### Reference server implementation

The coordinated maintained server, including a Docker deployment that bundles a
pinned Ravencoin Core 4.8.0 with ElectrumX, is at
[`ALENOC/electrumx-ravencoin`](https://github.com/ALENOC/electrumx-ravencoin).
It implements the compatible `server.ravencoin_backend` capability and enforces
the Core 4.8.0 floor on its own side. It is a reference implementation, not a
requirement: you do not have to use that server, or any ALENOC infrastructure,
to use this wallet.

## Security model

What this maintenance work changed:

- which Electrum servers are eligible on mainnet;
- backend Ravencoin Core validation and version comparison;
- server selection and fail-closed network behaviour;
- diagnostics and rejection messages.

What it did **not** change:

- seed generation and seed derivation;
- private key handling and storage;
- wallet encryption;
- the wallet file format;
- transaction signing;
- hardware wallet support and signing;
- asset signing semantics;
- NFC and unrelated wallet cryptography.

Existing wallet files keep working, and nothing about how your keys are created,
stored or used was reworked by this fork. The change is entirely about which
servers the wallet is willing to believe.

## Validation status

Honest current state, to be updated as milestones actually complete:

| Item | Status |
|---|---|
| Backend safety policy and fail-closed gates | IMPLEMENTED |
| Deterministic test coverage of the policy | AUTOMATED TESTED |
| Schema agreement with the maintained server | CONTRACT TESTED against the server's real response |
| Positive end-to-end run against a fully indexed live server | REAL LIVE INTEGRATION PENDING |

The reference server implementation is still completing its full mainnet Core
and ElectrumX historical index. Until that finishes, a live server correctly
reports `backendSynchronized: false` and `checkpoint4487775: false`, and this
wallet correctly refuses it. The positive `SAFE_CORE_VERIFIED` path is therefore
covered by deterministic and contract tests, and the real live run is not yet
claimed.

## Diagnostics

The connected-node view shows, for the selected server: the Electrum host,
ElectrumX version, Electrum protocol version, backend Core version and
subversion, backend network, backend height, the minimum safe Core the server
declares, the backend safety state, the chain validation state and the resulting
eligibility state. Rejection messages distinguish an old Core, an unverifiable
backend, wrong network, malformed evidence, a timeout, unsafe flags and a chain
conflict. Server responses are never logged verbatim, and no credential is ever
displayed or stored.

## Troubleshooting

**"Server rejected: Ravencoin Core x.y.z is below the minimum safe version
4.8.0"**
The server answered honestly and its backend is too old. Nothing is wrong with
your wallet. Use a server whose operator has upgraded to Core 4.8.0 or newer.

**Backend Core could not be verified**
The server either does not implement `server.ravencoin_backend` or returned
evidence that failed validation. Older servers predate the capability. This is
the expected outcome for unmaintained infrastructure.

**"Server rejected: backend reports the wrong Ravencoin network"**
The server is not proving Ravencoin mainnet. Check that you are not pointing a
mainnet wallet at a testnet server.

**Blockchain conflict**
The chain that server serves does not agree with expected Ravencoin history.
The server is quarantined rather than used. Do not override this.

**No safe server available, the wallet will not connect**
No candidate could prove a safe backend, so the wallet is staying offline on
purpose. It will connect as soon as one qualifies.

**`server.version` looks like a fine version but the server is still rejected**
`server.version` is the ElectrumX software version, not the Ravencoin Core
version. A server can run recent ElectrumX on top of an old, unpatched Core.
Only `server.ravencoin_backend` answers the question that matters.

**A server was fine a moment ago and is now ineligible**
Backend evidence has to be fresh, within five minutes of the wallet's clock. A
badly skewed system clock on either side can also cause this, so check the time
on your own machine.

## Getting started

There is currently **no ALENOC binary release** of this wallet. Run it from
source, as described below. The upstream build recipes still work, but no
official maintained-fork installer, AppImage, APK or macOS bundle is published,
and this document does not imply one exists.

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

A normal clone gives you the maintained code:
```
$ git clone https://github.com/ALENOC/electrum-ravencoin.git
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

The backend safety policy has its own focused suite, which is the fast way to
check that the Core 4.8+ gates still behave:
```
$ pytest electrum/tests/test_ravencoin_backend.py electrum/tests/test_interface.py -v
```

Some unrelated upstream tests in the wider suite are known to fail on current
dependencies for reasons predating this fork. Cryptography is never modified to
make them pass.

## Creating Binaries

These are the upstream build recipes. They are unchanged, and no maintained-fork
binary is published from them here.

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

## Credits and history

Thomas Voegtlin and the Electrum developers created the original Electrum
wallet. The Electrum-RVN-SIG community, including kralverde, performed the
Ravencoin conversion and the asset work this wallet depends on. ALENOC maintains
this safety fork on top of their work.

The distinction matters: the original upstream project is the wallet, and this
fork is a maintenance layer that changes which servers it will trust. Upstream
copyright notices, the MIT licence, acknowledgements and commit history are
preserved intact.
