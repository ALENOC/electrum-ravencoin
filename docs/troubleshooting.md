# Troubleshooting

Documentation: [Home](../README.md) · [Docs index](README.md) ·
[Server policy](server-policy.md) · [Security](security-model.md)

## No eligible server

This is expected when all candidates are syncing, stale, unreviewed or in chain
conflict. The wallet deliberately stays degraded rather than connecting to an
unverifiable endpoint.

## `CORE_UNREVIEWED_VERSION`

The exact repository and commit are absent from policy. This includes a future
4.9.0 even when its numeric version is higher than the certified baseline.

## `CORE_IDENTITY_CONFLICT`

The server's version may resemble a certified release, but its repository or
commit differs. Treat it as a different build and do not override the result.

## `BACKEND_UNSAFE` or `CHAIN_CONFLICT`

The backend is stale, unsynchronized, on the wrong network, missing required
flags/checkpoint evidence, or serving history that fails independent validation.
The operator must repair and revalidate the server; the wallet should not lower
its policy.

## Policy looks out of date

This build has no remote policy fetcher: the effective policy is the baseline
compiled into the wallet, and a revocation reaches users through a wallet
update. If you expected a specific release to already be certified or revoked,
check the wallet version rather than local cache or network state, and never
replace the policy file with unsigned JSON.
