# sugyeol

`sugyeol` (수결) is a single, statically linked Go binary for detached signatures, countersignature chains, container-image signatures, and signed split ZIP archives.

Korean documentation: [README_KO.md](README_KO.md)

## Build

```sh
make build
```

The build uses `CGO_ENABLED=0`, `netgo`, and `osusergo`. Linux release builds are checked with `file` to ensure that they are statically linked.

## Split archives

```sh
# Required once before the first signing operation.
sugyeol key init --name "Your Name" --email "you@example.com"

# Default: 100 MB per part. Unitless values are MB.
sugyeol pack -size 10 -scramble=true -out backup ./source
sugyeol verify backup.part-*.zip
sugyeol unpack -out ./restored backup.part-*.zip
```

`-scramble=false` stores the TAR fragments without the reversible XOR/SHA-256 transformation. SHA-256 and Ed25519 protection remains enabled either way. Scrambling is not encryption and provides no confidentiality.

For confidentiality, enable high-speed authenticated encryption:

```sh
# Interactive password entry (entered twice, never placed in the process list).
sugyeol pack -encrypt -size 100 -out secret ./source
sugyeol unpack -out ./restored secret.part-*.zip

# Automation: the password file must be a regular file with mode 0600 or stricter.
sugyeol pack -encrypt -password-file ./password.txt -out secret ./source
sugyeol unpack -password-file ./password.txt -out ./restored secret.part-*.zip
```

Encryption uses streaming 4 MiB AES-256-GCM chunks, allowing hardware acceleration without loading a whole part into memory. A 128-bit random salt and Argon2id (19 MiB, 2 passes) derive the key once per package. Every chunk has an authentication tag; KDF parameters, nonces, signer identity, hashes, and encryption mode are signed in each ZIP manifest. `-encrypt` supersedes scrambling. Password SHA values are deliberately not stored.

Every independently readable ZIP part contains only:

- `manifest.json`
- `signature.ed25519`
- `public_key.pem`
- `payload.scrambled`

The signed ZIP manifest contains original/scrambled SHA-256 values plus the initialized signer name/email, signing time, and a fresh 128-bit signature salt. The complete ZIP, including metadata and signatures, never exceeds `-size`. Supported units are `B`, `KB`, `MB`, `GB`, `TB`, `KiB`, `MiB`, `GiB`, and `TiB`.

## Detached signing

Files and complete directory trees can be signed without creating an archive:

```sh
sugyeol sign -label author -out source.meta ./source
sugyeol verify -source ./source source.meta

# Pin a trusted key to prove signer identity, not only integrity.
sugyeol key -out sugyeol-public.pem
sugyeol verify -source ./source -pubkey sugyeol-public.pem source.meta
```

The `.meta` JSON sidecar contains the canonical SHA-256 manifest and a signature chain. Every record contains the signer's initialized name/email, optional role label, signing time, random 128-bit salt, public key, manifest digest, and previous-record digest. All these fields are covered by Ed25519. The manifest includes sorted relative paths, file types, modes, sizes, and per-file SHA-256 hashes.

Additional parties can append signatures only after the existing chain and current source both verify:

```sh
# Run with the third party's own ~/.sugyeol identity.
sugyeol countersign -source ./source -label reviewer -pubkey author.pem source.meta

# Require two valid signatures and both independently trusted keys.
sugyeol verify -source ./source -min-signatures 2 \
  -pubkey author.pem -pubkey reviewer.pem source.meta
```

Changing the source or any earlier record makes countersigning fail without modifying `.meta`. Countersigning also requires at least one trusted existing signer via `-pubkey`, preventing an internally consistent attacker-created chain from being signed accidentally. The aliases `endorse`, `cosign`, and `co-sign` are also accepted. More records alone do not create more trust; independent pinned keys do.

Without `-pubkey`, verification proves that content still matches the embedded signing key but cannot establish who owns that key. Distribute the public-key fingerprint over a separate trusted channel.

## Keys

`sugyeol key init --name ... --email ...` creates the identity and private Ed25519 key. The private key exists only at `~/.sugyeol/ed25519_private.pem` with mode `0600`; `~/.sugyeol` is forced to mode `0700`. Identity metadata is stored in `~/.sugyeol/identity.json`. Signing is refused until initialization is complete. Private key export or alternate private-key locations are intentionally unsupported. Public keys are embedded in signed data and can be exported with `sugyeol key -out`.

## Container image signing

Sugyeol resolves an OCI/Docker registry tag to the exact manifest bytes and signs its immutable `sha256` digest. Multi-platform image indexes are signed as indexes rather than silently selecting one platform.

```sh
sugyeol image sign -label release registry.example.com/team/app:1.2.3
sugyeol image verify -pubkey release.pem app-<digest>.image.meta

# A second party verifies the remote manifest, existing chain, and trusted key first.
sugyeol image countersign -pubkey release.pem -label security-review app-<digest>.image.meta
sugyeol image verify -min-signatures 2 \
  -pubkey release.pem -pubkey reviewer.pem app-<digest>.image.meta
```

Authentication supports anonymous registries and standard Docker `config.json` basic/identity credentials with Bearer-token challenges. The signed `.image.meta` is an independent portable sidecar. v1.0 does not push the sidecar as an OCI 1.1 Referrers artifact; this avoids claiming interoperability on registries that only implement the fallback tag scheme.

## Internationalization

English and Korean are selected from `SUGYEOL_LANG`, `LC_ALL`, `LC_MESSAGES`, or `LANG`. Override per invocation:

```sh
sugyeol --lang ko help
sugyeol --lang en help
```

## Self-update

```sh
sugyeol update --check
sugyeol update
sugyeol update --version v1.0.0
```

The updater downloads the matching static binary from [GitHub Releases](https://github.com/ziozzang/sugyeol/releases), verifies it against the release `SHA256SUMS`, and atomically replaces the running executable. Interactive use performs a soft-failing release check at most once per 24 hours and only prints a notice; set `SUGYEOL_NO_UPDATE_CHECK=1` to disable it. Actual replacement always requires the explicit `sugyeol update` command.

## Release build

```sh
make release VERSION=1.0.0
```

This creates static Linux, macOS, and Windows artifacts for amd64 and arm64 plus `dist/SHA256SUMS`.
