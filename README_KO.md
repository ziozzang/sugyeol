# sugyeol

`sugyeol`(수결)은 독립 서명, 누적 countersignature 체인, 컨테이너 이미지 서명, 서명된 분할 ZIP과 복구를 제공하는 단일 정적 Go 바이너리입니다.

## 빌드

```sh
make build
```

`CGO_ENABLED=0`, `netgo`, `osusergo`로 빌드하며 Linux 릴리스는 실제 정적 링크 여부도 검사합니다.

## 분할 ZIP

```sh
# 최초 서명 전에 반드시 한 번 실행합니다.
sugyeol key init --name "홍길동" --email "you@example.com"

# 기본 파트 크기는 100 MB이며 단위 없는 숫자는 MB입니다.
sugyeol pack -size 10 -scramble=true -out backup ./source
sugyeol verify backup.part-*.zip
sugyeol unpack -out ./restored backup.part-*.zip
```

`-scramble=false`로 가역 스크램블링만 끌 수 있습니다. SHA-256과 Ed25519 서명은 항상 적용됩니다. 스크램블링은 암호화가 아니며 기밀성을 제공하지 않습니다.

기밀성이 필요하면 고속 인증 암호화를 사용합니다.

```sh
# 터미널에서 암호를 두 번 입력하며 프로세스 인자에는 노출되지 않습니다.
sugyeol pack -encrypt -size 100 -out secret ./source
sugyeol unpack -out ./restored secret.part-*.zip

# 자동화에서는 권한이 0600 이하인 일반 파일만 허용합니다.
sugyeol pack -encrypt -password-file ./password.txt -out secret ./source
sugyeol unpack -password-file ./password.txt -out ./restored secret.part-*.zip
```

4 MiB 단위 AES-256-GCM 스트리밍으로 전체 파트를 메모리에 올리지 않고 하드웨어 가속을 활용합니다. 128-bit 무작위 salt와 Argon2id(19 MiB, 2회)가 패키지당 한 번 키를 유도합니다. 모든 chunk에는 인증 tag가 있으며 KDF 매개변수, nonce, 서명자 identity, 해시, 암호화 방식은 ZIP manifest 서명에 포함됩니다. `-encrypt`는 스크램블링을 대체합니다. 비밀번호 SHA 값은 저장하지 않습니다.

각 ZIP은 `manifest.json`, `signature.ed25519`, `public_key.pem`, `payload.scrambled`만 포함합니다. 서명된 manifest에는 원본/스크램블 SHA-256과 초기화된 서명자 이름/이메일, 서명 시각, 매번 새로 생성한 128-bit salt가 포함됩니다. ZIP 헤더와 모든 메타데이터를 포함한 실제 파일 크기는 `-size`를 넘지 않습니다.

## 독립 서명

ZIP을 만들지 않고 파일이나 디렉터리 전체를 서명할 수 있습니다.

```sh
sugyeol sign -label author -out source.meta ./source
sugyeol verify -source ./source source.meta

# 신뢰된 공개키를 고정하면 서명자의 신원까지 확인할 수 있습니다.
sugyeol key -out sugyeol-public.pem
sugyeol verify -source ./source -pubkey sugyeol-public.pem source.meta
```

`.meta` JSON sidecar에는 canonical SHA-256 manifest와 누적 서명 체인이 들어갑니다. 각 레코드는 초기화된 서명자의 이름/이메일, 선택 역할 레이블, 서명 시각, 임의 128-bit salt, 공개키, manifest digest, 직전 레코드 digest를 가지며 이 모든 필드가 Ed25519 서명에 포함됩니다.

제3자는 기존 체인 전체와 현재 원본이 모두 무결할 때만 서명을 누적할 수 있습니다.

```sh
# 제3자 자신의 ~/.sugyeol identity로 실행합니다.
sugyeol countersign -source ./source -label reviewer -pubkey author.pem source.meta

# 유효한 서명 2개와 독립적으로 신뢰한 공개키 2개를 모두 요구합니다.
sugyeol verify -source ./source -min-signatures 2 \
  -pubkey author.pem -pubkey reviewer.pem source.meta
```

원본 또는 앞선 체인이 깨지면 `.meta`를 수정하지 않고 countersign이 실패합니다. 또한 `countersign`은 기존 서명자 중 최소 하나의 신뢰 공개키를 `-pubkey`로 반드시 요구하므로 공격자가 새로 만든 자기완결 체인을 실수로 승인하지 않습니다. `endorse`, `cosign`, `co-sign` 별칭도 지원합니다. 체인 길이만으로 신뢰가 늘지는 않으며 독립적으로 고정한 공개키가 중요합니다.

`-pubkey`가 없으면 내장 공개키 이후 데이터가 바뀌지 않았다는 무결성만 증명하며, 그 키의 소유자 신원은 증명하지 못합니다. 공개키 지문은 별도 신뢰 채널로 전달해야 합니다.

## 키

`sugyeol key init --name ... --email ...`로 identity와 개인키를 최초 생성합니다. 개인키는 `~/.sugyeol/ed25519_private.pem`에만 `0600` 권한으로 생성되며 `~/.sugyeol`은 `0700`으로 강제됩니다. 이름/이메일 등은 `~/.sugyeol/identity.json`에 저장되고 초기화 전에는 서명을 거부합니다. 개인키 내보내기나 다른 개인키 경로는 지원하지 않습니다. 공개키만 `sugyeol key -out`으로 내보낼 수 있습니다.

## 컨테이너 이미지 서명

OCI/Docker 레지스트리 태그가 가리키는 manifest 원문을 조회하고 변경 불가능한 `sha256` digest를 서명합니다. 멀티 플랫폼 이미지는 특정 플랫폼을 임의 선택하지 않고 image index 자체를 서명합니다.

```sh
sugyeol image sign -label release registry.example.com/team/app:1.2.3
sugyeol image verify -pubkey release.pem app-<digest>.image.meta

# 제3자는 원격 manifest, 기존 체인, 신뢰키를 모두 검증한 다음 서명합니다.
sugyeol image countersign -pubkey release.pem -label security-review app-<digest>.image.meta
sugyeol image verify -min-signatures 2 \
  -pubkey release.pem -pubkey reviewer.pem app-<digest>.image.meta
```

익명 레지스트리와 Docker `config.json`의 basic/identity 자격 증명 및 Bearer token challenge를 지원합니다. 결과는 독립적으로 전달 가능한 `.image.meta` sidecar입니다. v1.0에서는 OCI 1.1 Referrers artifact push는 지원하지 않습니다. 레지스트리별 fallback tag 호환성을 충분히 검증하지 않은 상태에서 상호운용성을 보장하지 않기 위함입니다.

## 다국어

`SUGYEOL_LANG`, `LC_ALL`, `LC_MESSAGES`, `LANG` 순서로 영어/한국어를 선택합니다.

```sh
sugyeol --lang ko help
sugyeol --lang en help
```

## 자동 업데이트

```sh
sugyeol update --check
sugyeol update
sugyeol update --version v1.0.0
```

플랫폼에 맞는 정적 바이너리를 GitHub Release에서 받고 `SHA256SUMS`를 검증한 다음 현재 실행 파일을 원자적으로 교체합니다. 터미널 실행 시 최대 24시간에 한 번 새 릴리스를 확인해 알림만 표시하며, 실제 교체는 명시적인 `sugyeol update`에서만 수행합니다. `SUGYEOL_NO_UPDATE_CHECK=1`로 자동 확인을 끌 수 있습니다.

## 릴리스 빌드

```sh
make release VERSION=1.0.0
```

Linux, macOS, Windows의 amd64/arm64 정적 바이너리 6개와 `SHA256SUMS`를 생성합니다.
