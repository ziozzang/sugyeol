# Sugyeol (수결)

English is the primary documentation. [한국어 문서](README_KO.md)

Sugyeol is one statically linked Go binary for signed split ZIP packages, detached file/directory signatures, cumulative countersignatures, container-image signatures, verification, restoration, and self-update.

Current release: **v1.1.0**. Source: <https://github.com/ziozzang/sugyeol>. Releases: <https://github.com/ziozzang/sugyeol/releases>.

## Build and install

Go 1.25 or newer is required to build. Release builds use `CGO_ENABLED=0`, `netgo`, and `osusergo`.

```sh
make build
./sugyeol version
file ./sugyeol
```

`make release VERSION=1.1.0` builds static Linux, macOS, and Windows binaries for x86-64 and ARM64 into `dist/`, plus `SHA256SUMS`.

## Initialize the signing identity

Signing is refused until an identity and key have been initialized.

```sh
sugyeol key init --name "Jane Doe" --email "jane@example.com"
# Short form
sugyeol key init -n "Jane Doe" -e "jane@example.com"

sugyeol key --out jane-public.pem
sugyeol key -o jane-public.pem
```

The Ed25519 private key is created only at `~/.sugyeol/ed25519_private.pem` with mode `0600`; `~/.sugyeol` is forced to `0700`. Identity metadata is stored in `~/.sugyeol/identity.json`. Sugyeol has no private-key export option and does not accept an alternate private-key path. Back up the home directory securely if key recovery is required.

## Pack signed split ZIP files

```sh
# Defaults: 100 MB per part, scrambling on, no ZIP compression.
sugyeol pack --out backup ./source

# A unitless size is decimal MB. Every resulting ZIP is at most 1900 MB.
sugyeol pack --size 1900 --out genos genos.tar

# Equivalent short form, with compression and scrambling disabled.
sugyeol pack -s 1900 -o genos -c highest -x=false genos.tar
```

Pack options:

| Long | Short | Default | Meaning |
|---|---:|---:|---|
| `--size` | `-s` | `100` | Maximum size of each complete ZIP. Unitless values are decimal MB; `MiB`, `GB`, etc. are accepted. |
| `--out` | `-o` | `package` | Output filename prefix. |
| `--scramble` | `-x` | `true` | Reversible XOR/SHA-256-counter scrambling. Use `-x=false` to disable. This is not encryption. |
| `--compression` | `-c` | `none` | ZIP payload compression: `none`, `fastest`, `default`, `highest`, or numeric `0..9`. |
| `--encrypt` | `-e` | `false` | Password-based authenticated encryption; overrides scrambling. |
| `--password-file` | `-p` | none | Read the password from a regular file whose permissions are `0600` or stricter. Requires encryption. |

Compression mapping:

| Value | ZIP method |
|---|---|
| `none`, `0` | Stored without compression; fastest and the default. |
| `fastest`, `1` | DEFLATE level 1. |
| `default` | Go DEFLATE default level. |
| `2` through `8` | Exact DEFLATE level. |
| `highest`, `9` | DEFLATE level 9. |

Scrambled or encrypted bytes are intentionally high-entropy and normally do not compress. Compression is most useful with `--scramble=false` and no encryption. The selected method and level are included in the signed manifest. Capacity calculation reserves ZIP metadata, encryption tags, and conservative worst-case DEFLATE expansion; the complete file, not just its payload, is checked against `--size`.

Every part is a normal `.zip` containing exactly:

- `manifest.json`: signed set/part metadata, hashes, signer identity, time, salt, compression, scrambling, and encryption parameters.
- `signature.ed25519`: signature of the canonical manifest.
- `public_key.pem`: signing public key.
- `payload.scrambled`: stored, compressed, scrambled, or encrypted TAR segment.

## High-speed encryption

```sh
# Interactive input is hidden and never placed in process arguments.
sugyeol pack -e -s 1900 -o secret ./source
sugyeol unpack -o ./restored secret.part-*.zip

# Automation
chmod 600 ./password.txt
sugyeol pack -e -p ./password.txt -o secret ./source
sugyeol unpack -p ./password.txt -o ./restored secret.part-*.zip
```

Encryption uses 4 MiB streaming AES-256-GCM chunks. Argon2id derives one package master key using a random 128-bit salt, 19 MiB memory, two passes, and one lane; HMAC-SHA-256 derives separate per-part AES keys. Each chunk has an authentication tag. Password hashes are not stored. An incorrect password, modified ciphertext, changed manifest, or mixed/missing part is rejected before successful restoration.

## Verify and restore packages

```sh
sugyeol verify backup.part-*.zip
sugyeol unpack --out ./restored backup.part-*.zip
sugyeol unpack -o ./restored backup.part-*.zip

# Pin the expected archive signer.
sugyeol verify --pubkey jane-public.pem backup.part-*.zip
sugyeol verify -k jane-public.pem backup.part-*.zip
```

Verification checks ZIP structure, canonical manifest encoding, Ed25519 signature, public-key consistency, SHA-256 payload hashes, part count/order/offsets, encryption/compression parameters, and the declared maximum size. Restoration repeats verification and then safely extracts the TAR while rejecting traversal paths, links, and unsupported entries.

## Detached file and directory signatures

```sh
sugyeol sign --label author --out source.meta ./source
sugyeol sign -l author -o source.meta ./source

sugyeol verify --source ./source --pubkey jane-public.pem source.meta
sugyeol verify -s ./source -k jane-public.pem source.meta
```

The `.meta` JSON sidecar contains a canonical SHA-256 manifest and a signature chain. Directory manifests deterministically cover paths, modes, sizes, and content hashes. With no pinned `--pubkey`, cryptographic integrity is proven but signer identity is not; distribute public-key fingerprints through an independent trusted channel.

## Cumulative countersignatures

A third party may add a signature only after the complete existing chain and current source have passed verification, and at least one existing signer is matched against an independently trusted public key.

```sh
sugyeol countersign \
  --source ./source --pubkey author.pem --label reviewer source.meta

sugyeol countersign -s ./source -k author.pem -l reviewer source.meta

sugyeol verify -s ./source -n 2 \
  -k author.pem -k reviewer.pem source.meta
```

`endorse`, `cosign`, and `co-sign` are aliases of `countersign`. Each new record signs the manifest digest and previous record digest plus signer name/email, role label, UTC signing time, public key, and a fresh random 128-bit salt. More signatures do not create trust by themselves; pinned keys do.

## Container-image signatures

```sh
sugyeol image sign -l release -o app.image.meta registry.example.com/team/app:1.2.3
sugyeol image verify -k release.pem app.image.meta
sugyeol image countersign -k release.pem -l security-review app.image.meta
sugyeol image verify -n 2 -k release.pem -k reviewer.pem app.image.meta
```

Sugyeol resolves the exact OCI/Docker manifest bytes and signs their immutable `sha256` digest. A multi-platform index is signed as an index. Anonymous access, Docker `config.json` basic/identity credentials, and Bearer-token challenges are supported. v1.0 stores the portable signature as an `.image.meta` sidecar; it does not push an OCI Referrers artifact.

Image-specific short options are `-o` (out), `-l` (label), `-i` (image override), `-k` (repeatable public key), and `-n` (minimum signatures).

## Internationalization

English is the default. Korean is selected by `SUGYEOL_LANG`, `LC_ALL`, `LC_MESSAGES`, or `LANG`, in that order, or explicitly:

```sh
sugyeol --lang en help
sugyeol --lang ko help
```

## Self-update

```sh
sugyeol update --check       # short: -c
sugyeol update --force       # short: -f
sugyeol update --version v1.1.0  # short: -v v1.1.0
```

The updater chooses the current platform asset from GitHub Releases, verifies it against `SHA256SUMS`, and atomically replaces the running executable. Interactive execution performs a soft-failing release check at most once per 24 hours and prints only a notice; actual replacement always requires `sugyeol update`. Set `SUGYEOL_NO_UPDATE_CHECK=1` to disable notices.

## Manual release process

GitHub Actions are intentionally disabled. Build, test, inspect checksums, and publish manually:

```sh
go test -race ./...
go vet ./...
make release VERSION=1.1.0
(cd dist && sha256sum -c SHA256SUMS)

gh release create v1.1.0 \
  dist/sugyeol_1.1.0_* dist/SHA256SUMS \
  --repo ziozzang/sugyeol --target main --title "Sugyeol v1.1.0"
```

## Security boundaries

- Scrambling is obfuscation, not confidentiality; use `--encrypt` for secrets.
- Public keys embedded in ZIP or `.meta` prove internal integrity, not real-world identity. Pin independently obtained keys with `--pubkey/-k`.
- The private key never leaves `~/.sugyeol` through a Sugyeol command.
- Compression is applied by ZIP after scrambling/encryption and is covered by the signed manifest.
- v1.0 container signatures are local sidecars; registry artifact publication and key revocation infrastructure are outside the current scope.
