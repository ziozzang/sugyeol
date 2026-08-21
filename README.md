# packer

`packer` is a single, statically linked Go binary for signed split ZIP archives and detached file/directory signatures. The repository name is intentionally `pakcer`, while the binary is named `packer`.

Korean documentation: [README_KO.md](README_KO.md)

## Build

```sh
make build
```

The build uses `CGO_ENABLED=0`, `netgo`, and `osusergo`. Linux release builds are checked with `file` to ensure that they are statically linked.

## Split archives

```sh
# Required once before the first signing operation.
packer key init --name "Your Name" --email "you@example.com"

# Default: 100 MB per part. Unitless values are MB.
packer pack -size 10 -scramble=true -out backup ./source
packer verify backup.part-*.zip
packer unpack -out ./restored backup.part-*.zip
```

`-scramble=false` stores the TAR fragments without the reversible XOR/SHA-256 transformation. SHA-256 and Ed25519 protection remains enabled either way. Scrambling is not encryption and provides no confidentiality.

Every independently readable ZIP part contains only:

- `manifest.json`
- `signature.ed25519`
- `public_key.pem`
- `payload.scrambled`

The signed ZIP manifest contains original/scrambled SHA-256 values plus the initialized signer name/email, signing time, and a fresh 128-bit signature salt. The complete ZIP, including metadata and signatures, never exceeds `-size`. Supported units are `B`, `KB`, `MB`, `GB`, `TB`, `KiB`, `MiB`, `GiB`, and `TiB`.

## Detached signing

Files and complete directory trees can be signed without creating an archive:

```sh
packer sign -label author -out source.meta ./source
packer verify -source ./source source.meta

# Pin a trusted key to prove signer identity, not only integrity.
packer key -out packer-public.pem
packer verify -source ./source -pubkey packer-public.pem source.sig.json
```

The `.meta` JSON sidecar contains the canonical SHA-256 manifest and a signature chain. Every record contains the signer's initialized name/email, optional role label, signing time, random 128-bit salt, public key, manifest digest, and previous-record digest. All these fields are covered by Ed25519. The manifest includes sorted relative paths, file types, modes, sizes, and per-file SHA-256 hashes.

Additional parties can append signatures only after the existing chain and current source both verify:

```sh
# Run with the third party's own ~/.packer identity.
packer endorse -source ./source -label reviewer -pubkey author.pem source.meta

# Require two valid signatures and both independently trusted keys.
packer verify -source ./source -min-signatures 2 \
  -pubkey author.pem -pubkey reviewer.pem source.meta
```

Changing the source or any earlier record makes endorsement fail without modifying `.meta`. Endorsement also requires at least one trusted existing signer via `-pubkey`, preventing an internally consistent attacker-created chain from being endorsed accidentally. More records alone do not create more trust; independent pinned keys do.

Without `-pubkey`, verification proves that content still matches the embedded signing key but cannot establish who owns that key. Distribute the public-key fingerprint over a separate trusted channel.

## Keys

`packer key init --name ... --email ...` creates the identity and private Ed25519 key. The private key exists only at `~/.packer/ed25519_private.pem` with mode `0600`; `~/.packer` is forced to mode `0700`. Identity metadata is stored in `~/.packer/identity.json`. Signing is refused until initialization is complete. Private key export or alternate private-key locations are intentionally unsupported. Public keys are embedded in signed data and can be exported with `packer key -out`.

## Internationalization

English and Korean are selected from `PACKER_LANG`, `LC_ALL`, `LC_MESSAGES`, or `LANG`. Override per invocation:

```sh
packer --lang ko help
packer --lang en help
```

## Self-update

```sh
packer update --check
packer update
packer update --version v1.0.0
```

The updater downloads the matching static binary from [GitHub Releases](https://github.com/ziozzang/pakcer/releases), verifies it against the release `SHA256SUMS`, and atomically replaces the running executable. Interactive use performs a soft-failing release check at most once per 24 hours and only prints a notice; set `PACKER_NO_UPDATE_CHECK=1` to disable it. Actual replacement always requires the explicit `packer update` command.

## Release build

```sh
make release VERSION=1.0.0
```

This creates static Linux, macOS, and Windows artifacts for amd64 and arm64 plus `dist/SHA256SUMS`.
