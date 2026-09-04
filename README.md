# Sugyeol (수결)

English is the primary documentation. [한국어 문서](README_KO.md)

<p align="center">
  <a href="https://commons.wikimedia.org/wiki/File:Sign_of_Taejong_of_Joseon.jpg">
    <img src="https://upload.wikimedia.org/wikipedia/commons/1/1c/Sign_of_Taejong_of_Joseon.jpg" width="260" alt="The sugyeol signature of King Taejong of Joseon">
  </a>
</p>

<p align="center"><em>A historical sugyeol: King Taejong's handwritten mark, circa 1400.</em></p>

Sugyeol is one statically linked Go binary for signed split ZIP packages, detached file/directory signatures, cumulative countersignatures, container-image pull/sign/verification, embedded SPDX 2.3 SBOM generation, restoration, and self-update.

Like its namesake—the traditional Korean handwritten mark used to authenticate a document—Sugyeol binds identity and integrity to a digital artifact.

```text
file / directory ──┬── sign ────────────────> .meta signature chain ──> verify
                  │
                  └── pack + optional encryption ──> signed split ZIPs ──> verify / unpack

registry image ─────── native pull ──> OCI tar/tgz ──> run / SPDX SBOM / sign / verify
```

The embedded or sidecar metadata records SHA-256, Ed25519 signatures, the public key, signer identity, signing time, and cumulative signature links. Private signing keys remain under `~/.sugyeol`.

Current release: **v1.5.0**. Source: <https://github.com/ziozzang/sugyeol>. Releases: <https://github.com/ziozzang/sugyeol/releases>.

## Build and install

Go 1.25 or newer is required to build. Release builds use `CGO_ENABLED=0`, `netgo`, and `osusergo`.

```sh
make build
./sugyeol version
file ./sugyeol
```

`make release VERSION=1.5.0` builds static Linux, macOS, and Windows binaries for x86-64 and ARM64 into `dist/`, plus `SHA256SUMS`.

## Progress, verbose output, debug output, and cancellation

Long-running work reports progress on `stderr`, while command results remain on their existing output stream. Interactive terminals get an updating bar with percentage, processed bytes, average `KiB/s`/`MiB/s`/`GiB/s`, and ETA. Non-interactive use gets concise start/completion records including elapsed time and average speed.

```sh
# Global UI options are placed before the command.
sugyeol --verbose image pull -o app.oci.tgz registry.example.com/team/app:1.2.3
sugyeol -v pack -s 1900 -o backup ./source
sugyeol --debug image verify app.oci.tgz app.image.meta

# Print periodic progress lines even when stderr is redirected or running in CI.
sugyeol --progress always pack -o backup ./source

# Disable progress UI completely.
sugyeol --progress never verify backup_part-*.zip
sugyeol --no-progress verify backup_part-*.zip
```

`--verbose/-v` adds per-file, per-part, and per-container-blob status. `--debug` implies verbose and adds timestamped operational diagnostics, but never prints passwords, private keys, bearer tokens, credential values, or Authorization headers. Progress is available for TAR creation, hashing/signing, encryption/scrambling, compression/ZIP writing, verification, restoration/extraction, OCI/docker archive inspection, registry downloads, and self-update downloads.

The default `--progress auto` uses a live bar only on a terminal. `always` emits periodic line-oriented percentages suitable for captured logs, and `never` disables progress output. Pressing Ctrl+C once requests graceful cancellation with exit status 130, closes active streams, and lets temporary-output cleanup run. A second Ctrl+C restores immediate operating-system termination if an operation cannot stop promptly.

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

# Instead of a size limit, create exactly 7 balanced, non-empty parts.
sugyeol pack --parts 7 --out genos genos.tar
sugyeol pack -n 7 -o genos genos.tar
```

Pack options:

| Long | Short | Default | Meaning |
|---|---:|---:|---|
| `--size` | `-s` | `100` | Maximum size of each complete ZIP. Unitless values are decimal MB; `MiB`, `GB`, etc. are accepted. |
| `--parts` | `-n` | disabled | Create exactly this many balanced, non-empty parts. Mutually exclusive with an explicitly supplied size. |
| `--out` | `-o` | `package` | Output filename prefix. |
| `--scramble` | `-x` | `true` | Reversible XOR/SHA-256-counter scrambling. Use `-x=false` to disable. This is not encryption. |
| `--compression` | `-c` | `none` | ZIP payload compression: `none`, `fastest`, `default`, `highest`, or numeric `0..9`. |
| `--encrypt` | `-e` | `false` | Password-based authenticated encryption; overrides scrambling. |
| `--password` | `-P` | none | Password text. Convenient for shell automation but exposed to process listings/history/logs. |
| `--password-file` | `-p` | none | Read the password from a regular file whose permissions are `0600` or stricter. Requires encryption. |

`--out foo` creates `foo_part-000001-of-00000N.zip`, etc. Large TAR and payload intermediates are created under `./tmp` on the current working filesystem instead of the system `/tmp`; Sugyeol removes each intermediate and removes `./tmp` when it is empty, including error and cancellation paths. Existing or concurrent contents under `./tmp` are never deleted.

Compression mapping:

| Value | ZIP method |
|---|---|
| `none`, `0` | Stored without compression; fastest and the default. |
| `fastest`, `1` | DEFLATE level 1. |
| `default` | Go DEFLATE default level. |
| `2` through `8` | Exact DEFLATE level. |
| `highest`, `9` | DEFLATE level 9. |

Scrambled or encrypted bytes are intentionally high-entropy and normally do not compress. Compression is most useful with `--scramble=false` and no encryption. The selected method and level are included in the signed manifest. Capacity calculation reserves ZIP metadata, encryption tags, and conservative worst-case DEFLATE expansion; the complete file, not just its payload, is checked against `--size`. Count mode distributes the TAR payload with at most a one-byte difference and records a conservative calculated maximum part size in every signed manifest.

Every part is a normal `.zip` containing exactly:

- `manifest.json`: signed set/part metadata, hashes, signer identity, time, salt, compression, scrambling, and encryption parameters.
- `signature.ed25519`: signature of the canonical manifest.
- `public_key.pem`: signing public key.
- `payload.scrambled`: stored, compressed, scrambled, or encrypted TAR segment.

## High-speed encryption

```sh
# Interactive input is hidden and never placed in process arguments.
sugyeol pack -e -s 1900 -o secret ./source
sugyeol unpack -o ./restored secret_part-*.zip

# Automation
chmod 600 ./password.txt
sugyeol pack -e -p ./password.txt -o secret ./source
sugyeol unpack -p ./password.txt -o ./restored secret_part-*.zip

# Literal shell option: supported, but visible to ps/history/logging.
sugyeol pack -e -P "automation-secret" -o secret ./source
sugyeol unpack -P "automation-secret" -o ./restored secret_part-*.zip
```

Encryption uses 4 MiB streaming AES-256-GCM chunks. Argon2id derives one package master key using a random 128-bit salt, 19 MiB memory, two passes, and one lane; HMAC-SHA-256 derives separate per-part AES keys. Each chunk has an authentication tag. Password hashes are not stored. Password precedence is literal `-P/--password`, protected `-p/--password-file`, then hidden terminal input; literal and file options are mutually exclusive. `pack -e` asks for a hidden password and confirmation when neither option is supplied. During unpack, Sugyeol first verifies the manifests and automatically asks only when it detects encryption and no password was supplied. Prefer the protected file for automation because literal command arguments may be exposed by `ps`, shell history, CI logs, or error reporting. An incorrect password, modified ciphertext, changed manifest, or mixed/missing part is rejected before successful restoration.

## Verify and restore packages

```sh
sugyeol unpack foo
sugyeol unpack foo bar

sugyeol verify backup_part-*.zip
sugyeol unpack --out ./restored backup_part-*.zip
sugyeol unpack -o ./restored backup_part-*.zip

# Pin the expected archive signer.
sugyeol verify --pubkey jane-public.pem backup_part-*.zip
sugyeol verify -k jane-public.pem backup_part-*.zip
```

Each unpack argument may be a package prefix (`foo`), a literal ZIP part, or a quoted glob. A prefix automatically discovers both current `foo_part-*.zip` and legacy `foo.part-*.zip` names. Multiple prefixes are grouped by their signed package set IDs, fully verified first, and then restored into the selected output directory. Sugyeol rejects a multi-package command when two packages would restore the same root name rather than silently overwrite one with the other.

Verification checks ZIP structure, canonical manifest encoding, Ed25519 signature, public-key consistency, SHA-256 payload hashes, part count/order/offsets, encryption/compression parameters, and the declared maximum size. Restoration repeats verification and then safely extracts the TAR while rejecting traversal paths, links, and unsupported entries.

Restoration also reapplies each file and directory's permission mode, modification time, and access time. Directory metadata is applied after its children so extraction does not disturb the original directory timestamps. Creation/birth time is retained in signed PAX metadata: Windows and macOS restore it, while Linux preserves it in the archive but cannot apply it because Linux exposes no API for setting filesystem birth time. Unix `ctime` is inode change time, not creation time, and is intentionally not forged. Ownership, ACLs, extended attributes, device nodes, and symbolic links are not restored; this avoids privilege-dependent or unsafe extraction behavior. Use `--verbose` to see restored metadata and any platform limitation.

### Signer and trust report

Successful verification does not stop at `signature OK`. Sugyeol prints enough signed metadata to audit who signed what and how that identity was trusted:

- signer name and email, optional role/label, and UTC signing time with nanosecond precision;
- Ed25519 public key and SHA-256 fingerprint;
- signature algorithm and value, manifest SHA-256, signed random salt, record SHA-256, and previous-record SHA-256;
- signature-chain position and `genesis` marker for the first signature;
- `trusted (matched a pinned public key)`, `chain-valid but not directly pinned`, or `embedded key only` trust status.

Split ZIP verification reports the package set ID, source, part count, TAR payload size, scrambling/encryption/compression configuration, signer, public key/fingerprint, and first/last part-signing times. `--verbose` additionally prints every part's signing time, salt, payload SHA-256, and stored-payload SHA-256. Every package part must carry the same signer name/email and public key.

Signing and countersigning commands print the same metadata for the record they just created. A displayed name or email is signed data, but it becomes an independently trusted identity only when the key is pinned with `--pubkey/-k`.

The signing time is a signed claim from the signer's local clock, not proof from an external timestamp authority. The signature detects later changes to that value; it cannot independently prove that the clock was accurate when signing.

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

## Download, sign, and verify container-image archives

```sh
# Pull directly from the registry without Docker/Podman and create an OCI tar.
sugyeol image pull -o app.oci.tar -p linux/amd64 registry.example.com/team/app:1.2.3

# A .tgz/.tar.gz output implies gzip; -z is also available.
sugyeol image pull -o app.oci.tgz -z -p linux/arm64 registry.example.com/team/app:1.2.3

# Docker is not required to create the archive. Import and run with an available runtime/tool.
docker load < app.oci.tar
docker run --pull=never --rm registry.example.com/team/app:1.2.3
nerdctl load -i app.oci.tar
ctr images import app.oci.tar
podman load -i app.oci.tar

# Generate a package/file-level SPDX 2.3 SBOM and optionally sign it.
sugyeol image sbom -o app.spdx.json app.oci.tar
sugyeol image sbom -S -l security-scan -o app.spdx.json app.oci.tar

# Verify the SBOM-to-archive binding, then its signer against a pinned key.
sugyeol image sbom verify app.oci.tar app.spdx.json
sugyeol image sbom verify -k scanner.pem app.oci.tar app.spdx.json app.spdx.json.meta

# Pull, generate an SBOM, and sign both artifacts in one operation.
sugyeol image pull -S -m app.image.meta -b app.spdx.json -B \
  -o app.oci.tar registry.example.com/team/app:1.2.3

# Pull all manifests in a multi-platform index.
sugyeol image pull -a -o app-all.oci.tar registry.example.com/team/app:1.2.3

# Pull, validate the manifest/blob graph, and sign the local archive in one command.
sugyeol image pull -S -l release -m app.image.meta \
  -o app.oci.tgz registry.example.com/team/app:1.2.3

# Existing OCI-layout and `docker save` tar/tgz files can be signed locally.
sugyeol image sign -l release -o app.image.meta app.oci.tgz
sugyeol image sign -l release -o docker-save.image.meta docker-save.tar

# Verification is local and does not contact the registry.
sugyeol image verify -k release.pem app.oci.tgz app.image.meta

# A third party can countersign only after archive, graph, chain, and trust checks.
sugyeol image countersign -k release.pem -l security-review app.oci.tgz app.image.meta
sugyeol image verify -n 2 -k release.pem -k reviewer.pem app.oci.tgz app.image.meta
```

`image pull` is a native Distribution API client; Docker, containerd, Podman, and nerdctl are neither invoked nor required. It downloads the selected manifest/index, config, and layer blobs, verifies every descriptor size and SHA-256, and writes a standard OCI Image Layout containing `oci-layout`, `index.json`, and content-addressed `blobs/sha256/...`. For interoperable import it writes all of the following metadata:

- OCI `org.opencontainers.image.ref.name` with the original tag;
- containerd/nerdctl `io.containerd.image.name` with the normalized fully qualified image name;
- Docker Image Spec v1.2 `manifest.json` with `Config`, `Layers`, and `RepoTags`, also consumed by Docker-compatible Podman/containers-image paths.

The resulting hybrid archive remains a valid OCI image layout while `docker load`, `nerdctl load`, `ctr images import`, OCI-aware Podman, and Skopeo-family tooling can recover the image reference through the metadata they understand. Tagged inputs such as `hello-world:latest` retain their repository and tag. Digest-only input has no truthful tag to restore and therefore imports by image ID/digest. Docker-compatible entries reference the already verified OCI blobs, so layer bytes are not duplicated or recompressed. The default platform is the current OS/architecture; use `-p/--platform os/arch[/variant]` or `-a/--all-platforms`. Anonymous access, Docker `config.json` basic/identity credentials, and Bearer-token challenges are supported.

Local signing accepts both OCI Image Layout archives and Docker `docker save` archives, uncompressed or gzip-compressed. Before signing, Sugyeol validates safe TAR paths, rejects links/special entries, checks OCI blob names against their content hashes, follows the complete index/manifest/config/layer descriptor graph, or checks Docker `manifest.json` references. The signature subject contains the root descriptors, references, `index.json` SHA-256, complete archive size/SHA-256, compression, and format. Consequently both semantic image mutation and byte-level archive mutation are detected offline.

`image sbom` is an embedded scanner adapted from the MIT-licensed [bongsu-scanner](https://github.com/ziozzang/bongsu-scanner); it does not invoke Syft, Trivy, Docker, or another SBOM executable. It merges image layers with OCI whiteout semantics, supports uncompressed, gzip, and zstd layers, hashes the resulting regular files, and catalogs Debian dpkg, Alpine apk, npm lockfiles, Go modules, Python requirements/dist-info, Cargo lockfiles, and Maven `pom.properties`. RPM Berkeley DB/SQLite package databases are not decoded yet. The SPDX root package contains the exact source archive SHA-256. `image sbom verify` recalculates that hash and can additionally validate the detached SBOM signature against one or more pinned Ed25519 public keys. A multi-platform archive must currently be scanned one platform at a time; pull it with `-p/--platform` rather than `-a/--all-platforms`.

Pull short options are `-o` (out), `-p` (platform), `-a` (all platforms), `-z` (gzip), `-S` (sign archive), `-m` (archive metadata), `-l` (label), `-b` (SBOM output), and `-B` (sign SBOM). SBOM uses `-o`, `-S`, `-l`; SBOM verification uses `-k`, `-n`. Sign/countersign use `-o`, `-l`, `-k`, and `-n` as applicable. Direct signing of a mutable repository/tag is intentionally not a primary operation; the downloaded immutable archive is the signed artifact.

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
sugyeol update --version v1.5.0  # short: -v v1.5.0
```

The updater chooses the current platform asset from GitHub Releases, verifies it against `SHA256SUMS`, and atomically replaces the running executable. Interactive execution performs a soft-failing release check at most once per 24 hours and prints only a notice; actual replacement always requires `sugyeol update`. Set `SUGYEOL_NO_UPDATE_CHECK=1` to disable notices.

## Manual release process

GitHub Actions are intentionally disabled. Build, test, inspect checksums, and publish manually:

```sh
go test -race ./...
go vet ./...
make release VERSION=1.5.0
(cd dist && sha256sum -c SHA256SUMS)

gh release create v1.5.0 \
  dist/sugyeol_1.5.0_* dist/SHA256SUMS \
  --repo ziozzang/sugyeol --target main --title "Sugyeol v1.5.0"
```

## Security boundaries

- Scrambling is obfuscation, not confidentiality; use `--encrypt` for secrets.
- Public keys embedded in ZIP or `.meta` prove internal integrity, not real-world identity. Pin independently obtained keys with `--pubkey/-k`.
- The private key never leaves `~/.sugyeol` through a Sugyeol command.
- Compression is applied by ZIP after scrambling/encryption and is covered by the signed manifest.
- Container signatures are local sidecars over validated OCI/docker archives; registry artifact publication and key revocation infrastructure are outside the current scope.

## License and image credit

Sugyeol is released under the [MIT License](LICENSE).

The README image is the [sugyeol signature of King Taejong of Joseon](https://commons.wikimedia.org/wiki/File:Sign_of_Taejong_of_Joseon.jpg), circa 1400. Wikimedia Commons identifies the work as [Public Domain](https://creativecommons.org/publicdomain/mark/1.0/).
