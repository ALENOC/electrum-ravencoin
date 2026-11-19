#!/usr/bin/env bash
# Start the packaged GUI offline with a temporary, empty wallet directory.
set -euo pipefail
scratch=$(mktemp -d)
scratch=$(cd "$scratch" && pwd -P)
version=$(python3 contrib/print_electrum_version.py)
"$@" gui --offline -v -D "$scratch/data" >"$scratch/startup.log" 2>&1 &
app_pid=$!
trap 'kill "$app_pid" 2>/dev/null || true; wait "$app_pid" 2>/dev/null || true' EXIT
for ((attempt=0; attempt<60; attempt++)); do
    if ! kill -0 "$app_pid" 2>/dev/null; then
        break
    fi
    if grep -Fq "Electrum version: $version - " "$scratch/startup.log" &&
       grep -Fq 'Qt GUI starting up' "$scratch/startup.log" &&
       grep -Fq "wallet path $scratch/data/wallets/default_wallet" "$scratch/startup.log"; then
        echo "Packaged GUI reached wallet selection."
        exit 0
    fi
    sleep 1
done
cat "$scratch/startup.log" >&2
exit 1
