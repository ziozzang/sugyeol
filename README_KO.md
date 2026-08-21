# packer

`packer`는 서명된 분할 ZIP, 복구, 독립 파일/디렉터리 서명을 제공하는 단일 정적 Go 바이너리입니다. GitHub 저장소명은 요청대로 `pakcer`, 실행 파일명은 `packer`입니다.

## 빌드

```sh
make build
```

`CGO_ENABLED=0`, `netgo`, `osusergo`로 빌드하며 Linux 릴리스는 실제 정적 링크 여부도 검사합니다.

## 분할 ZIP

```sh
# 최초 서명 전에 반드시 한 번 실행합니다.
packer key init --name "홍길동" --email "you@example.com"

# 기본 파트 크기는 100 MB이며 단위 없는 숫자는 MB입니다.
packer pack -size 10 -scramble=true -out backup ./source
packer verify backup.part-*.zip
packer unpack -out ./restored backup.part-*.zip
```

`-scramble=false`로 가역 스크램블링만 끌 수 있습니다. SHA-256과 Ed25519 서명은 항상 적용됩니다. 스크램블링은 암호화가 아니며 기밀성을 제공하지 않습니다.

각 ZIP은 `manifest.json`, `signature.ed25519`, `public_key.pem`, `payload.scrambled`만 포함합니다. 서명된 manifest에는 원본/스크램블 SHA-256과 초기화된 서명자 이름/이메일, 서명 시각, 매번 새로 생성한 128-bit salt가 포함됩니다. ZIP 헤더와 모든 메타데이터를 포함한 실제 파일 크기는 `-size`를 넘지 않습니다.

## 독립 서명

ZIP을 만들지 않고 파일이나 디렉터리 전체를 서명할 수 있습니다.

```sh
packer sign -label author -out source.meta ./source
packer verify -source ./source source.meta

# 신뢰된 공개키를 고정하면 서명자의 신원까지 확인할 수 있습니다.
packer key -out packer-public.pem
packer verify -source ./source -pubkey packer-public.pem source.sig.json
```

`.meta` JSON sidecar에는 canonical SHA-256 manifest와 누적 서명 체인이 들어갑니다. 각 레코드는 초기화된 서명자의 이름/이메일, 선택 역할 레이블, 서명 시각, 임의 128-bit salt, 공개키, manifest digest, 직전 레코드 digest를 가지며 이 모든 필드가 Ed25519 서명에 포함됩니다.

제3자는 기존 체인 전체와 현재 원본이 모두 무결할 때만 서명을 누적할 수 있습니다.

```sh
# 제3자 자신의 ~/.packer identity로 실행합니다.
packer endorse -source ./source -label reviewer -pubkey author.pem source.meta

# 유효한 서명 2개와 독립적으로 신뢰한 공개키 2개를 모두 요구합니다.
packer verify -source ./source -min-signatures 2 \
  -pubkey author.pem -pubkey reviewer.pem source.meta
```

원본 또는 앞선 체인이 깨지면 `.meta`를 수정하지 않고 endorse가 실패합니다. 또한 `endorse`는 기존 서명자 중 최소 하나의 신뢰 공개키를 `-pubkey`로 반드시 요구하므로 공격자가 새로 만든 자기완결 체인을 실수로 승인하지 않습니다. 체인 길이만으로 신뢰가 늘지는 않으며 독립적으로 고정한 공개키가 중요합니다.

`-pubkey`가 없으면 내장 공개키 이후 데이터가 바뀌지 않았다는 무결성만 증명하며, 그 키의 소유자 신원은 증명하지 못합니다. 공개키 지문은 별도 신뢰 채널로 전달해야 합니다.

## 키

`packer key init --name ... --email ...`로 identity와 개인키를 최초 생성합니다. 개인키는 `~/.packer/ed25519_private.pem`에만 `0600` 권한으로 생성되며 `~/.packer`는 `0700`으로 강제됩니다. 이름/이메일 등은 `~/.packer/identity.json`에 저장되고 초기화 전에는 서명을 거부합니다. 개인키 내보내기나 다른 개인키 경로는 지원하지 않습니다. 공개키만 `packer key -out`으로 내보낼 수 있습니다.

## 다국어

`PACKER_LANG`, `LC_ALL`, `LC_MESSAGES`, `LANG` 순서로 영어/한국어를 선택합니다.

```sh
packer --lang ko help
packer --lang en help
```

## 자동 업데이트

```sh
packer update --check
packer update
packer update --version v1.0.0
```

플랫폼에 맞는 정적 바이너리를 GitHub Release에서 받고 `SHA256SUMS`를 검증한 다음 현재 실행 파일을 원자적으로 교체합니다. 터미널 실행 시 최대 24시간에 한 번 새 릴리스를 확인해 알림만 표시하며, 실제 교체는 명시적인 `packer update`에서만 수행합니다. `PACKER_NO_UPDATE_CHECK=1`로 자동 확인을 끌 수 있습니다.

## 릴리스 빌드

```sh
make release VERSION=1.0.0
```

Linux, macOS, Windows의 amd64/arm64 정적 바이너리 6개와 `SHA256SUMS`를 생성합니다.
