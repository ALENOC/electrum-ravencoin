#!/bin/bash

# Installs btchip-python into the currently active Python environment.
#
# btchip-python is required by the Ledger plugin (legacy protocol and HW.1
# support). The published 0.1.32 sdist, which is the latest release, declares:
#
#     extras_require = {'smartcard': ['python-pyscard>=1.6.12-4build1']}
#
# "1.6.12-4build1" is not a valid PEP 440 version, so setuptools 66 and newer
# refuse to build the package and "pip install" fails with:
#
#     error in btchip-python setup command: 'extras_require' must be a
#     dictionary whose values are strings or lists of strings containing valid
#     project/version requirement specifiers
#
# Older setuptools accepts the string but does not run on Python 3.12, so there
# is no usable setuptools version to fall back to. This script downloads the
# sdist, verifies its published sha256 digest, rewrites the invalid version
# specifier and installs the result with build isolation disabled.

set -e

BTCHIP_VERSION="${BTCHIP_VERSION:-0.1.32}"
PYTHON="${PYTHON:-python3}"

if ! "$PYTHON" -c "import sys; sys.exit(0 if sys.prefix != sys.base_prefix else 1)"; then
    echo "warning: no virtual environment is active; installing into $("$PYTHON" -c 'import sys; print(sys.prefix)')" >&2
fi

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

echo "Resolving btchip-python==${BTCHIP_VERSION} sdist..."
"$PYTHON" - "$BTCHIP_VERSION" "$workdir" <<'PYEOF'
import hashlib
import json
import sys
import urllib.request

version, workdir = sys.argv[1], sys.argv[2]
url = f"https://pypi.org/pypi/btchip-python/{version}/json"
with urllib.request.urlopen(url) as response:
    meta = json.load(response)

sdists = [f for f in meta["urls"] if f["packagetype"] == "sdist"]
if not sdists:
    sys.exit(f"no sdist published for btchip-python {version}")
sdist = sdists[0]

with urllib.request.urlopen(sdist["url"]) as response:
    payload = response.read()

digest = hashlib.sha256(payload).hexdigest()
expected = sdist["digests"]["sha256"]
if digest != expected:
    sys.exit(f"sha256 mismatch for {sdist['filename']}: got {digest}, expected {expected}")

with open(f"{workdir}/{sdist['filename']}", "wb") as f:
    f.write(payload)

print(f"{sdist['filename']} verified (sha256 {digest})")
PYEOF

tar xzf "$workdir/btchip-python-${BTCHIP_VERSION}.tar.gz" -C "$workdir"
srcdir="$workdir/btchip-python-${BTCHIP_VERSION}"

echo "Patching invalid PEP 440 requirement in setup.py..."
sed -i.bak "s/python-pyscard>=1\.6\.12-4build1/python-pyscard>=1.6.12/" "$srcdir/setup.py"
rm -f "$srcdir/setup.py.bak"

"$PYTHON" -m pip install "setuptools>=68" wheel
"$PYTHON" -m pip install --no-build-isolation "$srcdir"

echo "btchip-python ${BTCHIP_VERSION} installed."
