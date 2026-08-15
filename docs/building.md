# Building

Documentation: [Home](../README.md) · [Docs index](README.md) ·
[Releases](releases.md)

## Source environment

The maintained fork currently documents source execution rather than a published
ALENOC binary:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[full]"
python -m electrum.electrum_ravencoin --help
```

The `full` extra includes GUI, cryptography and hardware dependencies where
supported by the packaging metadata. Platform-specific native dependencies may
be required; consult the existing `contrib/` build guides.

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
