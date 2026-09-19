# Electrum-Ravencoin 1.3.1

1.3.1 is the first maintained stable release of the 1.3 line. It supersedes the
1.3.0 release candidates, which could not connect to a correctly configured
certified backend and, once refused, could not display history at all.

## Connectivity and backend policy

- The Ravencoin Core user agent is read according to BIP 14, so a node started
  with `uacomment` set is accepted. A subversion such as
  `/Ravencoin:4.8.0(comment)/` was previously rejected as malformed backend
  evidence and the client disconnected from an otherwise healthy server. The
  version in front of the comment must still match `backend.versionNumber`, and
  a comment can neither contain a slash nor forge a second user agent section.
- The built-in safe-Core baseline mirrors the release set of signed policy v3:
  `RavenProject/Ravencoin` v4.8.0 at commit
  `22549129888d02e0e08fcdb9f96f3c699167e774` is `KNOWN_SAFE`, and the earlier
  `2miners/Ravencoin` anchor at commit
  `b60f50e04f1fba425b28804e61be2694faaf3469` is `REVOKED`. Identity remains
  repository plus commit: a version number alone never grants eligibility, and a
  revoked baseline entry can never be rehabilitated by a remote policy.
- A server that cannot serve a verifiable header chunk is now abandoned with a
  message naming the height, instead of being retried about once a second
  forever. A single damaged header on a server previously left the client
  reporting itself as offline with no stated reason and no failover.

## Wallet correctness

- The transaction history no longer raises
  `wallet.get_history() failed balance sanity-check`. Balances count only
  transactions the verifier has proven at their claimed height, and the history
  balance now follows the same rule instead of summing every transaction in the
  address history. A remaining disagreement is reported rather than terminating
  the GUI refresh loop.
- The update check accepts release-candidate version strings. Comparing against
  a running `1.3.0rc3` raised `ValueError: invalid version number '1.3.0rc3'` on
  every version announcement, which surfaced as a traceback from the main
  window. Pre-releases sort below the final release of the same number, and an
  unparsable announcement is logged instead of propagating.

## Build and documentation

- The source-distribution build image installs its toolchain from Debian's
  immutable archive. `deb.debian.org` stopped serving the package versions its
  Bullseye indexes reference, which failed the release workflow's source job and
  therefore blocked producing any release at all.
- The documented source install works as written: it installs `btchip-python`
  through `contrib/install_btchip_python.sh`, which repairs an invalid PEP 440
  requirement in the published sdist that setuptools 66 and newer reject, builds
  `libsecp256k1` through `contrib/make_libsecp256k1.sh`, and starts the wallet
  with `./run_electrum`. There is no `electrum.electrum_ravencoin` module to run
  with `python -m`.

## Distribution

This release ships:

- source distribution (`.tar.gz`)
- Linux x86_64 AppImage
- Windows executables produced by the repository's deterministic Wine build
- macOS x86_64 DMG

The macOS artifact is x86_64. Native Apple Silicon packaging can be added after
the current deterministic macOS pipeline has been ported and validated for
arm64.

OS-level code signing and notarization may not be present on every artifact.
Integrity is independently covered by the release `SHA256SUMS` manifest and the
dedicated offline Ed25519 release signature. Verify both before running a
binary.

## Important trust note

This client is a lightweight wallet. It does not replace full Ravencoin
consensus validation performed by Ravencoin Core. Its security model validates
and authorizes ElectrumX backends and SPV evidence within the capabilities of a
lightweight client.

This is a community-maintained Electrum-Ravencoin release and is not an official
release of the Ravencoin Foundation or the original Electrum project.
