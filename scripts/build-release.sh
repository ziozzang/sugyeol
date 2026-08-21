#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dist_dir="${root_dir}/dist"
release_version="${VERSION:-1.2.0}"

if [[ ! "${release_version}" =~ ^[0-9A-Za-z._-]+$ ]]; then
  echo "invalid VERSION: ${release_version}" >&2
  exit 1
fi

mkdir -p "${dist_dir}"
targets=(
  "darwin arm64 macos arm64"
  "darwin amd64 macos x86_64"
  "windows arm64 windows arm64"
  "windows amd64 windows x86_64"
  "linux arm64 linux arm64"
  "linux amd64 linux x86_64"
)
artifacts=()

for target in "${targets[@]}"; do
  read -r goos goarch platform arch <<<"${target}"
  extension=""
  if [[ "${goos}" == "windows" ]]; then extension=".exe"; fi
  filename="sugyeol_${release_version}_${platform}_${arch}${extension}"
  output="${dist_dir}/${filename}"
  echo "building ${filename}"
  (
    cd "${root_dir}"
    CGO_ENABLED=0 GOOS="${goos}" GOARCH="${goarch}" go build \
      -buildvcs=false -trimpath -tags="netgo,osusergo" \
      -ldflags="-s -w -buildid= -X main.version=${release_version}" -o "${output}" .
  )
  if ! go version -m "${output}" 2>&1 | grep -q 'CGO_ENABLED=0'; then
    echo "static build verification failed: ${filename}" >&2
    exit 1
  fi
  if [[ "${goos}" == "linux" ]] && ! file "${output}" | grep -q 'statically linked'; then
    echo "static link verification failed: ${filename}" >&2
    exit 1
  fi
  if [[ "${goos}" != "windows" ]]; then chmod 0755 "${output}"; else chmod 0644 "${output}"; fi
  artifacts+=("${filename}")
done

(
  cd "${dist_dir}"
  sha256sum "${artifacts[@]}" > SHA256SUMS
  chmod 0644 SHA256SUMS
)
echo "release artifacts written to ${dist_dir}"
