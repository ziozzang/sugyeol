# 수결(Sugyeol)

[English documentation](README.md)이 기본 문서이며 이 문서는 동일 기능의 한국어 보조 문서입니다.

수결은 서명된 분할 ZIP 패키지, 파일/디렉터리 독립 서명, 누적 countersignature, 컨테이너 이미지 서명, 검증, 복구, 자체 업데이트를 하나의 정적 Go 바이너리로 제공합니다.

현재 릴리스는 **v1.1.0**입니다. 소스: <https://github.com/ziozzang/sugyeol>, 릴리스: <https://github.com/ziozzang/sugyeol/releases>.

## 빌드와 설치

빌드에는 Go 1.25 이상이 필요합니다. 릴리스는 `CGO_ENABLED=0`, `netgo`, `osusergo`로 정적 빌드합니다.

```sh
make build
./sugyeol version
file ./sugyeol
```

`make release VERSION=1.1.0`은 Linux/macOS/Windows의 x86-64·ARM64 정적 바이너리와 `SHA256SUMS`를 `dist/`에 만듭니다.

## 서명자 초기화

서명 전에 이름과 이메일을 넣어 identity와 키를 반드시 초기화해야 합니다.

```sh
sugyeol key init --name "홍길동" --email "hong@example.com"
sugyeol key init -n "홍길동" -e "hong@example.com"

sugyeol key --out hong-public.pem
sugyeol key -o hong-public.pem
```

Ed25519 개인키는 `~/.sugyeol/ed25519_private.pem`에만 `0600`으로 생성되고 `~/.sugyeol`은 `0700`으로 강제됩니다. Identity는 `~/.sugyeol/identity.json`에 저장됩니다. 개인키 내보내기와 다른 개인키 경로 지정은 지원하지 않습니다. 키 복구가 필요하다면 홈 디렉터리를 별도의 안전한 방법으로 백업해야 합니다.

## 서명된 분할 ZIP 패킹

```sh
# 기본값: 파트당 100 MB, 스크램블링 사용, ZIP 무압축.
sugyeol pack --out backup ./source

# 단위 없는 크기는 decimal MB. 각 완성 ZIP은 절대 1900 MB를 넘지 않습니다.
sugyeol pack --size 1900 --out genos genos.tar

# 단축 옵션, 최고 압축, 스크램블링 해제.
sugyeol pack -s 1900 -o genos -c highest -x=false genos.tar
```

Pack 옵션:

| 긴 옵션 | 단축 | 기본값 | 의미 |
|---|---:|---:|---|
| `--size` | `-s` | `100` | 완성된 각 ZIP의 최대 크기. 단위 생략은 decimal MB이며 `MiB`, `GB` 등도 지원합니다. |
| `--out` | `-o` | `package` | 출력 파일 접두사입니다. |
| `--scramble` | `-x` | `true` | XOR/SHA-256-counter 가역 스크램블링. `-x=false`로 끕니다. 암호화가 아닙니다. |
| `--compression` | `-c` | `none` | ZIP payload 압축: `none`, `fastest`, `default`, `highest`, 숫자 `0..9`. |
| `--encrypt` | `-e` | `false` | 암호 기반 인증 암호화. 스크램블링을 대체합니다. |
| `--password-file` | `-p` | 없음 | `0600` 이하 권한의 일반 파일에서 암호를 읽습니다. 암호화 시에만 사용합니다. |

압축 값:

| 값 | ZIP 방식 |
|---|---|
| `none`, `0` | 무압축 Store. 가장 빠르며 기본값입니다. |
| `fastest`, `1` | DEFLATE 레벨 1. |
| `default` | Go DEFLATE 기본 레벨. |
| `2`~`8` | 지정한 DEFLATE 레벨. |
| `highest`, `9` | DEFLATE 레벨 9. |

스크램블링·암호화 결과는 고엔트로피이므로 보통 압축되지 않습니다. 압축은 `--scramble=false`이고 암호화하지 않을 때 가장 효과적입니다. 압축 방식과 레벨은 서명된 manifest에 포함됩니다. 파트 용량 계산은 ZIP 메타데이터, 암호화 tag, DEFLATE 최악 확장량을 보수적으로 예약하며 payload가 아니라 완성 파일 전체가 `--size` 이내인지 검사합니다.

각 파트는 다음 4개 항목만 가진 정상 `.zip`입니다.

- `manifest.json`: 세트/파트 정보, 해시, 서명자, 시각, salt, 압축·스크램블·암호화 매개변수.
- `signature.ed25519`: canonical manifest의 서명.
- `public_key.pem`: 서명 공개키.
- `payload.scrambled`: 저장·압축·스크램블·암호화된 TAR 조각.

## 고속 암호화

```sh
# 터미널 입력은 숨겨지며 프로세스 인자에 암호가 노출되지 않습니다.
sugyeol pack -e -s 1900 -o secret ./source
sugyeol unpack -o ./restored secret.part-*.zip

# 자동화
chmod 600 ./password.txt
sugyeol pack -e -p ./password.txt -o secret ./source
sugyeol unpack -p ./password.txt -o ./restored secret.part-*.zip
```

4 MiB 단위 AES-256-GCM 스트리밍을 사용합니다. Argon2id가 임의 128-bit salt, 19 MiB 메모리, 2회, 1 lane으로 패키지 master key를 한 번 유도하고 HMAC-SHA-256이 파트별 AES 키를 만듭니다. 모든 chunk에 인증 tag가 있습니다. 암호 SHA는 저장하지 않습니다. 틀린 암호, 변조된 ciphertext/manifest, 섞이거나 누락된 파트는 복구 성공 전에 거부됩니다.

## 패키지 검사와 복구

```sh
sugyeol verify backup.part-*.zip
sugyeol unpack --out ./restored backup.part-*.zip
sugyeol unpack -o ./restored backup.part-*.zip

# 기대한 서명 공개키 고정
sugyeol verify --pubkey hong-public.pem backup.part-*.zip
sugyeol verify -k hong-public.pem backup.part-*.zip
```

검사는 ZIP 구조, canonical manifest, Ed25519 서명, 파트 공개키 일치, SHA-256, 파트 개수·순서·offset, 압축·암호화 매개변수, 최대 파일 크기를 확인합니다. 복구는 이를 다시 확인한 뒤 TAR 경로 탈출, 링크, 지원하지 않는 항목을 거부하면서 안전하게 풉니다.

## 파일·디렉터리 독립 서명

```sh
sugyeol sign --label author --out source.meta ./source
sugyeol sign -l author -o source.meta ./source

sugyeol verify --source ./source --pubkey hong-public.pem source.meta
sugyeol verify -s ./source -k hong-public.pem source.meta
```

`.meta` JSON sidecar는 canonical SHA-256 manifest와 서명 체인을 담습니다. 디렉터리는 경로, mode, 크기, 내용 해시를 결정론적으로 포함합니다. `--pubkey`가 없으면 암호학적 무결성은 검증하지만 서명자의 현실 신원은 증명하지 못하므로 공개키 지문을 별도 신뢰 채널로 전달해야 합니다.

## 누적 countersignature

제3자는 기존 체인 전체와 현재 원본이 정상이고, 기존 서명자 중 최소 하나가 독립적으로 신뢰한 공개키와 일치할 때만 서명을 추가할 수 있습니다.

```sh
sugyeol countersign \
  --source ./source --pubkey author.pem --label reviewer source.meta

sugyeol countersign -s ./source -k author.pem -l reviewer source.meta

sugyeol verify -s ./source -n 2 \
  -k author.pem -k reviewer.pem source.meta
```

`endorse`, `cosign`, `co-sign`도 같은 명령입니다. 새 레코드는 manifest digest와 직전 레코드 digest, 서명자 이름/이메일, 역할, UTC 시각, 공개키, 새 128-bit salt를 함께 서명합니다. 체인 길이 자체가 신뢰를 만들지는 않으며 별도로 고정한 키가 중요합니다.

## 컨테이너 이미지 서명

```sh
sugyeol image sign -l release -o app.image.meta registry.example.com/team/app:1.2.3
sugyeol image verify -k release.pem app.image.meta
sugyeol image countersign -k release.pem -l security-review app.image.meta
sugyeol image verify -n 2 -k release.pem -k reviewer.pem app.image.meta
```

OCI/Docker manifest 원문을 조회해 변경 불가능한 `sha256` digest를 서명합니다. 멀티 플랫폼은 image index 자체를 서명합니다. 익명 접근, Docker `config.json` basic/identity credential, Bearer token challenge를 지원합니다. v1.0은 `.image.meta` sidecar를 사용하며 OCI Referrers artifact push는 하지 않습니다.

이미지 단축 옵션은 `-o`(out), `-l`(label), `-i`(image override), `-k`(반복 공개키), `-n`(최소 서명 수)입니다.

## 다국어

영문이 기본입니다. `SUGYEOL_LANG`, `LC_ALL`, `LC_MESSAGES`, `LANG` 순서로 한국어를 선택하거나 직접 지정합니다.

```sh
sugyeol --lang en help
sugyeol --lang ko help
```

## 자체 업데이트

```sh
sugyeol update --check          # 단축: -c
sugyeol update --force          # 단축: -f
sugyeol update --version v1.1.0 # 단축: -v v1.1.0
```

현재 플랫폼용 GitHub Release 자산을 받고 `SHA256SUMS`를 확인한 뒤 실행 파일을 원자 교체합니다. 대화형 실행은 최대 24시간에 한 번 실패 허용 방식으로 새 버전 알림만 확인하며 실제 교체에는 항상 `sugyeol update`가 필요합니다. `SUGYEOL_NO_UPDATE_CHECK=1`로 알림 확인을 끌 수 있습니다.

## 수동 릴리스

GitHub Actions는 의도적으로 비활성화했습니다. 직접 빌드·테스트·검사 후 게시합니다.

```sh
go test -race ./...
go vet ./...
make release VERSION=1.1.0
(cd dist && sha256sum -c SHA256SUMS)

gh release create v1.1.0 \
  dist/sugyeol_1.1.0_* dist/SHA256SUMS \
  --repo ziozzang/sugyeol --target main --title "Sugyeol v1.1.0"
```

## 보안 경계

- 스크램블링은 난독화이며 기밀성을 제공하지 않습니다. 비밀 데이터에는 `--encrypt`를 사용합니다.
- ZIP/`.meta` 내장 공개키는 내부 무결성을 보일 뿐 현실 신원을 보장하지 않습니다. 별도로 받은 키를 `--pubkey/-k`로 고정합니다.
- 수결 명령을 통해 개인키가 `~/.sugyeol` 밖으로 내보내지지 않습니다.
- ZIP 압축은 스크램블링/암호화 뒤 적용되며 압축 설정은 manifest 서명 범위입니다.
- v1.0 컨테이너 서명은 로컬 sidecar입니다. 레지스트리 artifact 게시와 키 폐기 인프라는 현재 범위 밖입니다.
