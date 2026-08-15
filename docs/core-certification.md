# Core certification

Documentation: [Home](../README.md) · [Docs index](README.md) ·
[Security model](security-model.md)

## Release identity

The initial certified release is:

- repository: `2miners/Ravencoin`
- tag: `v4.8.0`
- commit: `b60f50e04f1fba425b28804e61be2694faaf3469`
- profile: `rvn-consensus-2026-08-v1`, revision 1
- profile SHA256: `1342d079f2eef7ae0803a247d2908c4b031ee4a542b0f837210f92ba36ae27b2`

The 12 mandatory release tests passed with no failures, reviews or skips. The
certification report and signed policies are preserved in the maintained server
repository under `core-safety/production/`.

## Release versus deployment

Release certification tests the exact software behavior using bounded,
deterministic fixtures. It does not prove that a third-party server runs that
binary. Live deployment checks—backend evidence, checkpoint presence, chain
validation, indexes and ElectrumX readiness—remain separate.

## Future releases

The watcher considers both `2miners/Ravencoin` and `RavenProject/Ravencoin`.
Each candidate must resolve to an exact commit, build, pass behavior tests and
be signed into a policy. A version number or GitHub release announcement does
not bypass this process.
