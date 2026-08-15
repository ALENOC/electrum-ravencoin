# Server policy

Documentation: [Home](../README.md) · [Docs index](README.md) ·
[Security model](security-model.md) · [Troubleshooting](troubleshooting.md)

## Three identities

- The wallet application's own version.
- `server.version`: ElectrumX software identity.
- `server.ravencoin_backend`: Ravencoin Core backend evidence.

The first two do not establish Core safety. The backend response must be present,
well formed, fresh and consistent. Its repository and exact commit must match a
`KNOWN_SAFE` entry in the signed policy, including the required profile.

## Runtime gates

The server must report the correct Ravencoin network, synchronized blocks and
headers, safe backend flags, verified checkpoint and fresh observation. The
wallet then independently validates chain identity and continuity. A safe policy
entry alone cannot override a chain conflict.

## Common states

| State | Meaning |
|---|---|
| `SAFE_CORE_VERIFIED` | Exact policy identity and all live checks pass |
| `CORE_UNREVIEWED_VERSION` | Version is absent from policy, including future releases |
| `CORE_IDENTITY_CONFLICT` | Same version exists, but repository/commit differs |
| `CORE_REVOKED` | Previously safe identity has been revoked |
| `BACKEND_UNSAFE` | Fresh evidence fails network, sync or safety requirements |
| `CHAIN_CONFLICT` | Independent validation disagrees with the server |
| `UNREACHABLE` | Transport failed or timed out |

## Policy availability

The static policy artifact is distributed over HTTPS and verified locally. If it
is unavailable, the client keeps its last verified policy or baseline. It does
not call a GitHub API at connection time and does not lower the acceptance bar.
