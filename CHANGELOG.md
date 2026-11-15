# Changelog

All notable changes to **shi-secrets** are recorded here.

This file starts at 0.10.0, the first release that needed one. Notes for 0.1.0
through 0.9.1 are on the repository's GitHub Releases page and are not
back-filled here, because inventing entries after the fact produces a changelog
nobody can trust.

Versioning is semantic with a `0.` major, so a **minor may break**: SwiftPM
treats `0.y.z` the way it treats a major, and consumers declaring
`from: "0.9.1"` do **not** pick up `0.10.0` automatically.

## 0.10.0 — 2026-11-15

### Changed

- **`swift-crypto` floor raised from `3.0.0` to `4.5.2`** (#55, merged
  2026-11-07). shi-secrets' own source is unchanged by this, and
  that is measured rather than assumed: #55 touched exactly two files,
  `Package.swift` (one line) and `Package.resolved` (six), and **no source
  file at all**. The `Crypto` surface this package actually uses is
  `Curve25519` (28 references), `SymmetricKey` (12), `SHA256` (7), `HMAC` (5)
  and `HKDF` (4), across 14 files that `import Crypto` — all spelled
  identically in 3.x and 4.x, so no call site had to move.

  **Why it is a release and not a detail.** Every fleet package that links
  `CoreKit` 0.14.0 or newer already requires `swift-crypto` 4.5.2+, and the
  released 0.9.1 pins 3.x. Those two ranges are disjoint, so
  `swift package resolve` *refuses* any graph holding both — there is no
  "newest wins" for version ranges. The fix has sat on `main` since 2026-11-07
  and reached nobody, because SwiftPM resolves tags, not branches. Two
  consumers were blocked on exactly this and said so in their own manifests:
  `ShikkiMCP` left `ProductionBrokerClient` unwired with the reason written
  into `Package.swift`, and the AIKit epic could not be consumed by
  `shikki#1930`.

### Added

- `LICENSE` — the verbatim GNU AGPL-3.0 text (#57). The repository previously
  carried no licence file at all, which means all rights reserved by default:
  a contributor legally could not touch it.
- `NOTICE` — names OBYW.one SASU as the copyright holder and Jeoffrey Thirot
  as the author.

### Why this is a minor, not a patch or a major

The public API of every product — `ShiSecretsKit`, `ShiSecretsDrivers`,
`ShiSecretsClient`, `ShiSecretsCLI`, `ShiSecrets` — is **unchanged**: no type,
member or signature was added, removed or altered.

It is not a **patch**, because a dependency's major range is part of what a
consumer resolves. Raising the floor can make a graph that resolved before
refuse to resolve now, and a change that can break `swift package resolve` is
not a bug fix.

It is not a **major** under this project's own numbering, because the `0.`
major already carries that meaning for SwiftPM: `0.10.0` is as breaking as a
consumer's resolver can treat it, and nothing in the source demands more.

### Consumers float to this release automatically

`from:` in SwiftPM means **up to the next major**, and for a `0.x` version the
next major is `1.0.0` — so a consumer declaring `from: "0.9.1"` *is* in range for
`0.10.0`. Only `.upToNextMinor(from:)` would exclude it.

Measured rather than reasoned: a probe package whose only dependency is
`.package(url: ".../shi-secrets.git", from: "0.9.1")` resolves
**shi-secrets 0.10.0** with `swift-crypto 4.5.2`, exit 0.

So `shikki` (`from: "0.9.1"`) and `shi-env` (`from: "0.1.0"`) pick this up on
their next resolve with no edit, and `swift-crypto` 4.x arrives with it. No
product API changed, so the API surface they see is identical; what reaches them
is the dependency major. `ShikkiMCP` declares no dependency on shi-secrets yet
and still needs its line added.

A probe pairing shi-secrets `0.10.0` with CoreKit `from: "0.17.0"` resolves both,
with `swift-crypto 4.5.2`, exit 0 — which is the conflict this release exists to
remove.
