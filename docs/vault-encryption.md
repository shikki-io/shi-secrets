# Vault encryption — what happens to a secret between `shi secret set` and the disk

> **Status:** the encryption described here landed 2026-09-03. Everything
> written before that date is **plaintext on the server** and must be
> re-encrypted and rotated. See [Migration](#migration).

## The model, in one paragraph

Vaultwarden is **zero-knowledge**. The server stores bytes it cannot read and
never inspects them. Every user-visible string in a vault item — the name, the
notes, each custom field — is an `EncString`, encrypted on the client. The
server's job is storage and access control, not confidentiality.

The consequence that matters when writing a client: **the server will accept
anything.** POST a plaintext string where an EncString belongs and you get
`200 OK`. There is no validation, no warning, no error. A green test suite
against your own client proves nothing, because your client reads back exactly
what it wrote.

## The bug this document exists because of

`VaultwardenClient.createCipher` assigned the plaintext name and value straight
into the request body, under this comment:

```
/// Vaultwarden accepts plaintext when accessed via API key
/// (client_credentials grant). No client-side encryption needed.
```

The first sentence is true. The second does not follow from it. Two things
were broken for as long as that code shipped:

1. **Interop.** Nothing shi-secrets wrote was readable by any Bitwarden
   client. The web vault showed `[error: cannot decrypt]`; the desktop app and
   the browser extension, which are stricter, dropped the items and showed an
   **empty vault**. This is what surfaced the problem.
2. **Confidentiality.** Every secret was stored **in the clear** on the
   server — and therefore in every backup, every `pg_dump`, and every restore
   into another environment. This is the serious one, and it was invisible.

`fetchSecret` read `notes` back raw, so read and write were wrong in the same
direction. The system was self-consistent and appeared to work end to end.

### Why the API key looked like a reason to skip encryption

This is the honest part, and it is a real wall, not carelessness.

The `client_credentials` grant authenticates **the call**. It does not unlock
**the data**. The token response carries the account's symmetric key in a field
named `Key` — but wrapped under a key derived from the *master password*. An
API key alone genuinely cannot decrypt anything.

The conclusion drawn was "so encryption is not possible here". The correct
conclusion is "so an unattended process needs an unlock step". That is
[`VaultUnlock`](../Sources/ShiSecretsKit/Auth/VaultUnlock.swift).

## The key ladder

```
master password ──PBKDF2-SHA256(salt = email, N iterations)──▶ masterKey (32B)
                          │
                          ├─HKDF-Expand(info: "enc")──▶ stretched enc (32B)
                          └─HKDF-Expand(info: "mac")──▶ stretched mac (32B)
                                        │
   account `Key`  (an EncString) ───decrypt──▶ userKey (64B)
                                        │
                        enc = userKey[0..<32]   mac = userKey[32..<64]
                                        │
   item name / notes / fields ──encrypt / decrypt──▶ EncString
```

* The PBKDF2 salt is the account email **lowercased and trimmed**. Getting
  that normalisation wrong yields a different key with no error anywhere.
* HKDF **expand only** — no extract step. The master key is already the PRK.
* `N` comes from `POST /identity/accounts/prelogin`, which is unauthenticated
  by design: the parameters are needed before login is possible. Our account
  reports PBKDF2-SHA256 with **600 000** iterations.
* Argon2id (`kdf: 1`) is **refused by name**. Deriving with the wrong KDF
  produces a key that fails to unwrap with no explanation, which is exactly
  the kind of silent wrongness this whole document is about.

## The wire format

```
2.<base64 iv>|<base64 ciphertext>|<base64 mac>
```

| type | scheme | we read | we write |
| --- | --- | --- | --- |
| 0 | AES-256-CBC, no MAC | yes | **no** — unauthenticated CBC is malleable |
| 2 | AES-256-CBC + HMAC-SHA256 | yes | yes |
| 1, 3–6 | RSA and other schemes | no | no |

Rules the implementation holds to, each of which is a known way to get this
wrong:

* **Encrypt-then-MAC over `iv ‖ ciphertext`**, verified **before** decrypting.
  Decrypting first turns the endpoint into a padding oracle.
* **Constant-time MAC comparison** (`HMAC.isValidAuthenticationCode`). A `==`
  on `Data` leaks the position of the first differing byte.
* **A fresh random IV per encryption.** Reusing one across two values under the
  same key reveals whether their first 16 bytes are equal.
* **A locked vault refuses to write.** There is deliberately no fallback that
  passes the plaintext through when no key is held — that fallback is the bug.

## Unlock, and the operator's constraint

> "I don't want to type a different password than mine, and I want the bot to
> be capable alone. If someone steals my mac, it cannot log in."

Both hold, in this shape:

* The master password is typed **once**, at unlock. It is never stored, never
  written to disk, never put in an environment variable, never logged.
* What survives is the 64-byte `userKey`. The bot holds it and runs unattended
  for the life of the session.
* The password **cannot be recovered** from the userKey, so a dump of broker
  memory does not yield the vault login.
* At rest the Keychain item is `WhenUnlockedThisDeviceOnly`: a stolen,
  powered-off machine has no key, and the item does not travel in a backup.

A wrong master password surfaces as `macMismatch` when the account key is
unwrapped. The server is never consulted and could not help — it does not know
the password either.

## Migration

Existing plaintext items are still **readable** — by shi-secrets, which is what
wrote them. They are not lost, and they must not be deleted to "clean up".

Two operations exist on `VaultwardenClient`:

```swift
// 1. See the blast radius. Needs NO key and NO unlock — "is this string
//    shaped like an EncString" is decidable without one, so this runs even
//    on a machine that cannot decrypt.
let audit = try await client.auditEncryption()
//    → total, encrypted, plaintext, plaintextNames, isClean

// 2. Dry run FIRST. Changes nothing; reports exactly what a real run would do.
let plan = try await client.reEncryptLegacyPlaintext(dryRun: true)

// 3. For real. Requires the vault to be unlocked.
let done = try await client.reEncryptLegacyPlaintext(dryRun: false)
//    → examined, rewritten, alreadyEncrypted, failures[name: reason]
```

> **Not yet reachable from the CLI.** These are Kit-level APIs. Exposing them
> as `shi secret audit-encryption` / `shi secret migrate --re-encrypt` needs
> two new verbs on the broker wire protocol and an authorization scope for
> them — a verb that rewrites *every* secret in the vault should not inherit
> `secret.set`'s scope by default. That is the next commit, deliberately
> separated from the cryptography so each can be reviewed on its own terms.

`fetchSecret` tolerates plaintext during this window and prints a warning once
per process. The tolerance is removed when the audit reports zero.

**Re-encrypting is not rotating.** It hides the values from *future* readers of
the database. It does nothing about backups already taken, dumps already made,
or anyone who has already looked. Every credential that was stored in the clear
must still be rotated at its source.

## Tests

`Tests/ShiSecretsKitTests/Auth/BitwardenCryptoTests.swift` — 23 tests. The two
that matter most, because they are the ones the original code would fail:

* **the key ladder is checked against a vector computed outside Swift**, so it
  cannot confirm itself;
* **`ciphertext does not contain the plaintext`**.

`Tests/ShiSecretsE2ETests/SecretsLifecycleRealVaultwardenTests.swift` asserts
what the *server* holds, not just what the client reads back. Restoring the old
plaintext write makes those five assertions fail — while `set`, `get`, `list`
and `delete` all still pass, which is precisely why the defect survived a green
suite.
