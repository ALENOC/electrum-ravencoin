# Building

Documentation: [Home](../README.md) · [Docs index](README.md) ·
[Releases](releases.md)

## Source environment

The maintained fork currently documents source execution rather than a published
ALENOC binary:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
./contrib/install_btchip_python.sh
python -m pip install -e ".[full]"
./contrib/make_libsecp256k1.sh
./run_electrum --help
```

The `full` extra includes GUI, cryptography and hardware dependencies where
supported by the packaging metadata. Platform-specific native dependencies may
be required; consult the existing `contrib/` build guides.

### btchip-python

`btchip-python` 0.1.32, the latest release, ships a `setup.py` that declares
`python-pyscard>=1.6.12-4build1` as an extra requirement. That version string is
not valid PEP 440, so setuptools 66 and newer abort the build:

```text
error in btchip-python setup command: 'extras_require' must be a dictionary
whose values are strings or lists of strings containing valid project/version
requirement specifiers
```

Downgrading setuptools is not a workaround, because releases old enough to
accept the string fail on Python 3.12 with `module 'pkgutil' has no attribute
'ImpImporter'`. Run `contrib/install_btchip_python.sh` before the editable
install instead. It fetches the sdist, verifies the published sha256 digest,
rewrites the version specifier and installs the package, after which
`pip install -e ".[full]"` finds the dependency already satisfied.

The dependency is only needed by the Ledger plugin for the legacy protocol and
HW.1 devices, but the plugin imports it together with `ledger_bitcoin`, so a
missing `btchip` module disables Ledger support entirely.

### libsecp256k1

`contrib/make_libsecp256k1.sh` builds the pinned upstream `libsecp256k1` and
places `libsecp256k1.so.2` inside the `electrum/` package directory. Skipping it
leaves the wallet unable to start:

```text
ImportError: Failed to load libsecp256k1
```

### Running the wallet

Use `./run_electrum` from the source tree, or the `electrum_ravencoin` console
script installed into the environment. `setup.py` ships the entry point as a
script, not as an importable module, so `python -m electrum.electrum_ravencoin`
fails with `No module named electrum.electrum_ravencoin`.

## Checks

Run the focused policy/backend/directory tests before distributing a build:

```sh
python -m pytest -q electrum/tests/test_core_safety_policy.py \
  electrum/tests/test_core_safety_directory.py \
  electrum/tests/test_ravencoin_backend.py
```

Do not describe a locally built binary as an ALENOC release unless it is
distributed through the maintained release process and its exact identity is
documented.
