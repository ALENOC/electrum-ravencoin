# Core certification

Documentation: [Home](../README.md) · [Docs index](README.md) ·
[Security model](security-model.md)

## Release identity

The certified release is:

- repository: `RavenProject/Ravencoin`
- tag: `v4.8.0`
- commit: `22549129888d02e0e08fcdb9f96f3c699167e774`
- profile: `rvn-consensus-2026-08-v1`, revision 2
- profile SHA256: `8606d330e917414d75bfd0225804faa1ca3a3593f6886e0ac5347fc7444ebd40`
- certification report digest: `949ec5eb66fc5fef709a75073bb5aba8964b1212e4b407369aace0cde3a34045`

The initial anchor, `2miners/Ravencoin` at commit
`b60f50e04f1fba425b28804e61be2694faaf3469`, is `REVOKED`: 2miners is not a trust
source, and it is superseded by the RavenProject-only Core trust root. A
revoked identity in the built-in baseline can never be rehabilitated by a remote
policy.

Both entries mirror signed safe-Core policy v3, whose signature verifies under
the Ed25519 key `a6b89849cec9eab7` pinned in `electrum/core_safety_policy.py`.
The certification report and signed policies are preserved in the maintained
server repository under `core-safety/production/`.

The built-in baseline deliberately does not mirror the signed policy's
`expiresAt`: a baseline that expires would leave a wallet with no policy at all.

## Release versus deployment

Release certification tests the exact software behavior using bounded,
deterministic fixtures. It does not prove that a third-party server runs that
binary. Live deployment checks (backend evidence, checkpoint presence, chain
validation, indexes and ElectrumX readiness) remain separate.

## Future releases

The watcher considers both `2miners/Ravencoin` and `RavenProject/Ravencoin`.
Each candidate must resolve to an exact commit, build, pass behavior tests and
be signed into a policy. A version number or GitHub release announcement does
not bypass this process.
