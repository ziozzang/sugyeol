# 수결(Sugyeol)

[English documentation](README.md)이 기본 문서이며 이 문서는 동일 기능의 한국어 보조 문서입니다.

<p align="center">
  <a href="https://commons.wikimedia.org/wiki/File:Sign_of_Taejong_of_Joseon.jpg">
    <img src="https://upload.wikimedia.org/wikipedia/commons/1/1c/Sign_of_Taejong_of_Joseon.jpg" width="260" alt="조선 태종의 수결 서명">
  </a>
</p>

<p align="center"><em>약 1400년경 조선 태종의 실제 수결.</em></p>

수결은 서명된 분할 ZIP 패키지, 파일/디렉터리 독립 서명, 누적 countersignature, 컨테이너 이미지 다운로드/서명/검증, 내장 SPDX 2.3 SBOM 생성, 복구, 자체 업데이트를 하나의 정적 Go 바이너리로 제공합니다.

전통적인 수결이 문서에 작성자의 신원과 진위를 새겼듯이, 이 도구는 디지털 파일에 서명자의 신원과 무결성을 결합합니다.

```text
파일 / 디렉터리 ──┬── sign ────────────────> .meta 서명 체인 ──> verify
                 │
                 └── pack + 선택적 암호화 ──> 서명된 분할 ZIP ──> verify / unpack

원격 컨테이너 이미지 ── 네이티브 pull ──> OCI tar/tgz ──> 실행 / SPDX SBOM / 서명 / 검증
```

ZIP 내부 또는 sidecar 메타데이터에는 SHA-256, Ed25519 서명, 공개키, 서명자 신원, 서명 시각과 누적 서명 연결 정보가 기록됩니다. 개인 서명키는 `~/.sugyeol` 아래에만 유지됩니다.

현재 릴리스는 **v1.6.0**입니다. 소스: <https://github.com/ziozzang/sugyeol>, 릴리스: <https://github.com/ziozzang/sugyeol/releases>.

## 빌드와 설치

빌드에는 Go 1.25 이상이 필요합니다. 릴리스는 `CGO_ENABLED=0`, `netgo`, `osusergo`로 정적 빌드합니다.

```sh
make build
./sugyeol version
file ./sugyeol
```

`make release VERSION=1.6.0`은 Linux/macOS/Windows의 x86-64·ARM64 정적 바이너리와 `SHA256SUMS`를 `dist/`에 만듭니다.

## 진행률·상세 출력·디버그·취소

오래 걸리는 작업의 진행 UI는 `stderr`로 출력하고 명령 결과는 기존 출력 채널을 유지합니다. 대화형 터미널에서는 bar graph, 퍼센트, 처리량/전체량, 평균 `KiB/s`·`MiB/s`·`GiB/s`, 경과시간, ETA를 함께 보여줍니다. 아직 전체량을 모르는 탐색·네트워크 단계는 움직이는 activity bar와 경과시간을 표시합니다. 비대화형 실행은 시작·완료·경과시간·평균속도를 간결한 로그로 남기고 `--progress always`에서는 주기적인 진행 로그도 출력합니다.

```sh
# 전역 UI 옵션은 명령 앞에 둡니다.
sugyeol --verbose image pull -o app.oci.tgz registry.example.com/team/app:1.2.3
sugyeol -v pack -s 1900 -o backup ./source
sugyeol --debug image verify app.oci.tgz app.image.meta

# stderr redirect나 CI에서도 주기적인 진행률 줄을 출력합니다.
sugyeol --progress always pack -o backup ./source

# 진행 UI를 완전히 끕니다.
sugyeol --progress never verify backup_part-*.zip
sugyeol --no-progress verify backup_part-*.zip
```

`--verbose/-v`는 파일·파트·컨테이너 blob별 상태를 추가합니다. `--debug`는 verbose를 포함하고 시각이 붙은 동작 진단을 보여주지만 비밀번호, 개인키, bearer token, credential 값과 Authorization header는 출력하지 않습니다. TAR 생성, 해시/서명, 암호화/스크램블링, 압축/ZIP 기록, 검증, 복구/추출, OCI/docker 아카이브 검사, registry 다운로드와 자체 업데이트 다운로드에 진행률을 제공합니다.

기본 `--progress auto`는 터미널에서만 live bar를 사용합니다. `always`는 수집 로그에 적합한 줄 단위 퍼센트를 주기적으로 출력하고 `never`는 진행 출력을 끕니다. Ctrl+C를 한 번 누르면 종료 코드 130으로 정상 취소를 요청하고 열린 stream을 닫은 뒤 임시 출력 정리 절차를 실행합니다. 작업이 즉시 중단되지 않으면 두 번째 Ctrl+C로 운영체제의 즉시 종료 동작을 사용할 수 있습니다.

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

# 크기 대신 비어 있지 않은 균등 파트 7개를 정확히 생성합니다.
sugyeol pack --parts 7 --out genos genos.tar
sugyeol pack -n 7 -o genos genos.tar
```

Pack 옵션:

| 긴 옵션 | 단축 | 기본값 | 의미 |
|---|---:|---:|---|
| `--size` | `-s` | `100` | 완성된 각 ZIP의 최대 크기. 단위 생략은 decimal MB이며 `MiB`, `GB` 등도 지원합니다. |
| `--parts` | `-n` | 사용 안 함 | 비어 있지 않은 균등 파트를 정확히 지정 개수로 생성합니다. 명시한 size와 함께 쓸 수 없습니다. |
| `--out` | `-o` | `package` | 출력 파일 접두사입니다. |
| `--scramble` | `-x` | `true` | XOR/SHA-256-counter 가역 스크램블링. `-x=false`로 끕니다. 암호화가 아닙니다. |
| `--compression` | `-c` | `none` | ZIP payload 압축: `none`, `fastest`, `default`, `highest`, 숫자 `0..9`. |
| `--encrypt` | `-e` | `false` | 암호 기반 인증 암호화. 스크램블링을 대체합니다. |
| `--password` | `-P` | 없음 | 암호 문자열. 셸 자동화에는 편하지만 프로세스 목록/history/log에 노출될 수 있습니다. |
| `--password-file` | `-p` | 없음 | `0600` 이하 권한의 일반 파일에서 암호를 읽습니다. 암호화 시에만 사용합니다. |

`--out foo`를 지정하면 `foo_part-000001-of-00000N.zip` 형식으로 생성됩니다. 대용량 TAR·payload 임시 파일은 시스템 `/tmp`가 아니라 실행한 현재 파일시스템의 `./tmp` 아래에 만들며, 정상 종료뿐 아니라 오류·취소 시에도 개별 임시 파일을 지우고 비어 있는 `./tmp`를 제거합니다. 기존 파일이나 동시에 실행 중인 작업이 `./tmp`에 있으면 삭제하지 않습니다.

압축 값:

| 값 | ZIP 방식 |
|---|---|
| `none`, `0` | 무압축 Store. 가장 빠르며 기본값입니다. |
| `fastest`, `1` | DEFLATE 레벨 1. |
| `default` | Go DEFLATE 기본 레벨. |
| `2`~`8` | 지정한 DEFLATE 레벨. |
| `highest`, `9` | DEFLATE 레벨 9. |

스크램블링·암호화 결과는 고엔트로피이므로 보통 압축되지 않습니다. 압축은 `--scramble=false`이고 암호화하지 않을 때 가장 효과적입니다. 압축 방식과 레벨은 서명된 manifest에 포함됩니다. 파트 용량 계산은 ZIP 메타데이터, 암호화 tag, DEFLATE 최악 확장량을 보수적으로 예약하며 payload가 아니라 완성 파일 전체가 `--size` 이내인지 검사합니다. 개수 모드는 TAR payload를 최대 1바이트 차이로 균등 분배하고 계산한 보수적 최대 파트 크기를 모든 서명 manifest에 기록합니다.

각 파트는 다음 4개 항목만 가진 정상 `.zip`입니다.

- `manifest.json`: 세트/파트 정보, 해시, 서명자, 시각, salt, 압축·스크램블·암호화 매개변수.
- `signature.ed25519`: canonical manifest의 서명.
- `public_key.pem`: 서명 공개키.
- `payload.scrambled`: 저장·압축·스크램블·암호화된 TAR 조각.

## 고속 암호화

```sh
# 터미널 입력은 숨겨지며 프로세스 인자에 암호가 노출되지 않습니다.
sugyeol pack -e -s 1900 -o secret ./source
sugyeol unpack -o ./restored secret_part-*.zip

# 자동화
chmod 600 ./password.txt
sugyeol pack -e -p ./password.txt -o secret ./source
sugyeol unpack -p ./password.txt -o ./restored secret_part-*.zip

# 문자열 옵션도 지원하지만 ps/history/log에서 보일 수 있습니다.
sugyeol pack -e -P "automation-secret" -o secret ./source
sugyeol unpack -P "automation-secret" -o ./restored secret_part-*.zip
```

4 MiB 단위 AES-256-GCM 스트리밍을 사용합니다. Argon2id가 임의 128-bit salt, 19 MiB 메모리, 2회, 1 lane으로 패키지 master key를 한 번 유도하고 HMAC-SHA-256이 파트별 AES 키를 만듭니다. 모든 chunk에 인증 tag가 있으며 암호 SHA는 저장하지 않습니다. 암호 우선순위는 문자열 `-P/--password`, 보호된 `-p/--password-file`, 숨김 터미널 입력이며 문자열과 파일 옵션은 함께 쓸 수 없습니다. `pack -e`는 두 옵션이 없으면 숨김 암호와 확인 암호를 묻습니다. Unpack은 manifest를 먼저 검사해 암호화를 감지하고 전달된 암호가 없을 때만 자동으로 숨김 입력을 띄웁니다. 문자열 인자는 `ps`, shell history, CI log, 오류 출력에 노출될 수 있으므로 자동화에는 보호된 파일 방식을 권장합니다. 틀린 암호, 변조된 ciphertext/manifest, 섞이거나 누락된 파트는 복구 성공 전에 거부됩니다.

## 패키지 검사와 복구

```sh
sugyeol unpack foo
sugyeol unpack foo bar
sugyeol unpack foo_part-000001
sugyeol unpack .
sugyeol unpack -y . # 비대화형 덮어쓰기 승인

sugyeol verify backup_part-*.zip
sugyeol unpack --out ./restored backup_part-*.zip
sugyeol unpack -o ./restored backup_part-*.zip

# 기대한 서명 공개키 고정
sugyeol verify --pubkey hong-public.pem backup_part-*.zip
sugyeol verify -k hong-public.pem backup_part-*.zip
```

unpack의 각 인자는 패키지 접두사(`foo`), ZIP 파트 경로, 파트 파일명의 일부(`foo_part-000`), 따옴표로 감싼 glob 패턴 또는 디렉터리일 수 있습니다. `sugyeol unpack .`은 현재 디렉터리의 모든 패키지를 찾습니다. 접두사는 현재 형식인 `foo_part-*.zip`과 기존 `foo.part-*.zip`을 모두 자동 탐색합니다. 파일명 일부는 일치하는 모든 서명 package set을 선택하고 같은 디렉터리의 나머지 파트도 모두 찾습니다. 선택된 묶음은 package set ID로 구분해 모두 먼저 검증한 뒤 복구합니다. 여러 패키지의 복구 루트가 겹치면 대화형 실행은 뒤 패키지로 덮어쓸지 묻고, 자동화에서는 `--overwrite`/`-y`로 명시해야 합니다.

검사는 ZIP 구조, canonical manifest, Ed25519 서명, 파트 공개키 일치, SHA-256, 파트 개수·순서·offset, 압축·암호화 매개변수, 최대 파일 크기를 확인합니다. 복구는 이를 다시 확인한 뒤 TAR 경로 탈출, 링크, 지원하지 않는 항목을 거부하면서 안전하게 풉니다.

복구 시 각 파일과 디렉터리의 권한 mode, 수정 시각(mtime), 접근 시각(atime)도 다시 적용합니다. 자식 파일 생성으로 디렉터리 시각이 바뀌지 않도록 디렉터리 메타데이터는 마지막에 역순으로 복원합니다. 생성 시각(birth/creation time)은 서명 대상인 PAX 메타데이터에 보존하며 Windows와 macOS에서는 실제로 복원합니다. Linux는 파일시스템 birth time을 설정하는 API가 없으므로 패키지 안에는 보존하지만 복구된 inode에는 적용할 수 없습니다. Unix의 `ctime`은 생성 시각이 아니라 inode 변경 시각이므로 위조하지 않습니다. 소유권, ACL, 확장 속성, device node, 심볼릭 링크는 권한 의존성과 안전 문제 때문에 복원하지 않습니다. `--verbose`에서 복원한 메타데이터와 플랫폼 제약을 확인할 수 있습니다.

### 서명자와 신뢰 상태 보고

검증 성공 시 단순히 `서명 검증 완료`만 출력하지 않고 누가 무엇에 서명했고 그 신원을 어떻게 신뢰했는지 감사할 수 있는 메타데이터를 보여줍니다.

- 서명자 이름·이메일, 선택적 역할/라벨, nanosecond 정밀도의 UTC 서명 시각
- Ed25519 공개키와 SHA-256 지문
- 서명 알고리즘과 서명값, manifest SHA-256, 서명된 임의 salt, 레코드 SHA-256, 이전 레코드 SHA-256
- 서명 체인 위치와 최초 서명의 `genesis` 표시
- `고정한 공개키와 일치`, `체인은 유효하지만 직접 고정하지 않음`, `내장 공개키만 확인` 신뢰 상태

분할 ZIP 검증은 패키지 set ID, 원본명, 파트 수, TAR payload 크기, 스크램블링·암호화·압축 설정, 서명자, 공개키/지문과 최초·마지막 파트 서명 시각을 출력합니다. `--verbose`에서는 모든 파트의 서명 시각, salt, 원본 payload SHA-256과 저장 payload SHA-256도 보여줍니다. 한 패키지의 모든 파트는 동일한 서명자 이름·이메일·공개키를 가져야 합니다.

sign과 countersign 명령도 방금 생성한 레코드의 동일한 메타데이터를 출력합니다. 화면에 표시된 이름·이메일은 서명된 데이터이지만 `--pubkey/-k`로 공개키를 고정했을 때만 독립적으로 신뢰한 신원이 됩니다.

서명 시각은 외부 timestamp authority의 증명이 아니라 서명자 로컬 시계에서 가져온 서명된 주장입니다. 이후 시각 값의 변조는 탐지하지만 서명 당시 시계가 정확했다는 사실까지 독립적으로 증명하지는 않습니다.

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

## 컨테이너 이미지 아카이브 다운로드·서명·검증

```sh
# Docker/Podman 없이 레지스트리에서 직접 받아 OCI tar를 만듭니다.
sugyeol image pull -o app.oci.tar -p linux/amd64 registry.example.com/team/app:1.2.3

# alpine:latest를 받되 runtime에는 alpine:260904로 import되게 합니다.
sugyeol image pull -t alpine:260904 -o alpine.oci.tar alpine:latest

# .tgz/.tar.gz 출력은 gzip을 자동 선택하며 -z도 쓸 수 있습니다.
sugyeol image pull -o app.oci.tgz -z -p linux/arm64 registry.example.com/team/app:1.2.3

# 아카이브 생성에는 Docker가 필요 없습니다. 설치된 런타임/도구로 가져오고 실행할 수 있습니다.
docker load < app.oci.tar
docker run --pull=never --rm registry.example.com/team/app:1.2.3
nerdctl load -i app.oci.tar
ctr images import app.oci.tar
podman load -i app.oci.tar

# 패키지/파일 수준 SPDX 2.3 SBOM을 만들고 선택적으로 서명합니다.
sugyeol image sbom -o app.spdx.json app.oci.tar
sugyeol image sbom -S -l security-scan -o app.spdx.json app.oci.tar

# 한 플랫폼을 선택하거나 디렉터리에 플랫폼별 서명 SBOM을 만듭니다.
sugyeol image sbom -p linux/arm64 -o app-arm64.spdx.json app-all.oci.tar
sugyeol image sbom -a -S -o ./app-sboms app-all.oci.tar

# SBOM과 아카이브의 결합을 검사한 뒤 고정한 공개키로 서명자도 검증합니다.
sugyeol image sbom verify app.oci.tar app.spdx.json
sugyeol image sbom verify -k scanner.pem app.oci.tar app.spdx.json app.spdx.json.meta

# 다운로드, SBOM 생성, 두 산출물 서명을 한 번에 수행합니다.
sugyeol image pull -S -m app.image.meta -b app.spdx.json -B \
  -o app.oci.tar registry.example.com/team/app:1.2.3

# 모든 manifest를 받고 같은 작업에서 플랫폼별 SBOM도 만듭니다.
sugyeol image pull -a -b ./app-sboms -o app-all.oci.tar registry.example.com/team/app:1.2.3

# 다운로드·manifest/blob 그래프 검증·로컬 아카이브 서명을 한 번에 수행합니다.
sugyeol image pull -S -l release -m app.image.meta \
  -o app.oci.tgz registry.example.com/team/app:1.2.3

# 기존 OCI layout 및 `docker save` tar/tgz도 로컬에서 서명합니다.
sugyeol image sign -l release -o app.image.meta app.oci.tgz
sugyeol image sign -l release -o docker-save.image.meta docker-save.tar

# 검증은 로컬에서 수행하며 레지스트리에 접속하지 않습니다.
sugyeol image verify -k release.pem app.oci.tgz app.image.meta

# 제3자 누적 서명도 아카이브·그래프·체인·신뢰키 검증 후에만 가능합니다.
sugyeol image countersign -k release.pem -l security-review app.oci.tgz app.image.meta
sugyeol image verify -n 2 -k release.pem -k reviewer.pem app.oci.tgz app.image.meta
```

`image pull`은 Distribution API를 직접 사용하는 네이티브 클라이언트이며 Docker, containerd, Podman, nerdctl을 호출하지도 필요로 하지도 않습니다. 선택한 manifest/index, config, layer blob을 받고 모든 descriptor 크기와 SHA-256을 검사한 뒤 `oci-layout`, `index.json`, content-addressed `blobs/sha256/...`를 담은 표준 OCI Image Layout을 만듭니다. 상호운용 가능한 import를 위해 다음 메타데이터를 모두 기록합니다.

- 원래 태그를 담은 OCI `org.opencontainers.image.ref.name`
- 정규화한 전체 이미지명을 담은 containerd/nerdctl `io.containerd.image.name`
- `Config`, `Layers`, `RepoTags`를 담은 Docker Image Spec v1.2 `manifest.json` — Docker 호환 Podman/containers-image 경로에서도 사용

결과물은 유효한 OCI Image Layout인 동시에 `docker load`, `nerdctl load`, `ctr images import`, OCI-aware Podman과 Skopeo 계열 도구가 각자 이해하는 메타데이터로 이미지 참조명을 복원할 수 있는 하이브리드 아카이브입니다. `hello-world:latest` 같은 태그 입력은 저장소명과 태그를 유지합니다. Digest만 지정한 입력에는 사실인 태그가 없으므로 image ID/digest로 가져옵니다. Docker 호환 항목은 이미 검증된 OCI blob을 그대로 참조하므로 layer를 복제하거나 재압축하지 않습니다. 기본 플랫폼은 현재 OS/아키텍처이고 `-p/--platform os/arch[/variant]` 또는 `-a/--all-platforms`를 쓸 수 있습니다. 익명 접근, Docker `config.json` basic/identity credential, Bearer token challenge를 지원합니다.

로컬 서명은 무압축/gzip OCI Image Layout과 Docker `docker save` 아카이브를 모두 인식합니다. 서명 전 안전한 TAR 경로만 허용하고 링크/특수 항목을 거부하며, OCI blob 이름과 실제 content hash를 대조하고 index/manifest/config/layer descriptor 전체 그래프를 따라가거나 Docker `manifest.json` 참조를 검사합니다. 서명 subject에는 root descriptor, reference, `index.json` SHA-256, 완성 아카이브 크기/SHA-256, 압축 방식과 포맷이 들어갑니다. 따라서 이미지 의미 변조와 아카이브 바이트 변조를 모두 오프라인에서 탐지합니다.

`image sbom`은 MIT 라이선스 [bongsu-scanner](https://github.com/ziozzang/bongsu-scanner)의 스캐너를 수결에 맞게 가져온 내장 기능이며 Syft, Trivy, Docker 또는 별도 SBOM 실행 파일을 호출하지 않습니다. OCI whiteout 규칙에 따라 image layer를 합치고 무압축/gzip/zstd layer를 처리하며 최종 regular file을 모두 해시합니다. 네이티브 cataloger는 Debian dpkg, Alpine apk, RPM Berkeley DB/NDB/SQLite, 설치된 npm package와 npm/yarn/pnpm lock, Python requirements/dist-info/egg-info/Pipenv/Poetry/uv/pyenv/venv/Conda, Go module, Cargo, Maven metadata, Ruby Bundler/gemspec, PHP Composer, .NET assets/deps/lock, Swift Package Manager, Dart Pub을 지원합니다. 인식한 database를 해석하지 못하면 조용히 누락하지 않고 화면 경고와 SPDX package comment에 남깁니다. SPDX root package는 원본 archive SHA-256, 선택한 플랫폼, 가능한 경우 OCI manifest digest, OS와 catalog 범위를 묶습니다. `image sbom verify`는 archive hash를 다시 계산하며 고정한 Ed25519 공개키로 detached SBOM 서명도 검증할 수 있습니다. `-p/--platform`은 한 플랫폼, `-a/--all-platforms`는 출력 디렉터리에 플랫폼별 SPDX와 선택적 `.meta` 서명을 만듭니다.

Pull 단축 옵션은 `-o`(out), `-p`(platform), `-a`(전체 플랫폼), `-t`(import 이름/tag 강제), `-z`(gzip), `-S`(archive 서명), `-m`(archive metadata), `-l`(label), `-b`(SBOM 출력), `-B`(SBOM 서명)입니다. `-t/--tag`는 완전한 `repository:tag` 또는 원본 repository에 적용할 tag 하나만 받을 수 있으며, 검증된 image content가 아니라 archive 참조 metadata만 변경합니다. SBOM은 `-o`, `-p`, `-a`, `-S`, `-l`, SBOM 검증은 `-k`, `-n`을 씁니다. Sign/countersign에는 상황에 따라 `-o`, `-l`, `-k`, `-n`을 씁니다. 변경 가능한 리포지터리/태그 자체를 직접 서명하는 것은 기본 기능으로 두지 않고, 다운로드한 불변 아카이브를 서명 대상으로 삼습니다.

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
sugyeol update --version v1.6.0 # 단축: -v v1.6.0
```

현재 플랫폼용 GitHub Release 자산을 받고 `SHA256SUMS`를 확인한 뒤 실행 파일을 원자 교체합니다. 대화형 실행은 최대 24시간에 한 번 실패 허용 방식으로 새 버전 알림만 확인하며 실제 교체에는 항상 `sugyeol update`가 필요합니다. `SUGYEOL_NO_UPDATE_CHECK=1`로 알림 확인을 끌 수 있습니다.

## 수동 릴리스

GitHub Actions는 의도적으로 비활성화했습니다. 직접 빌드·테스트·검사 후 게시합니다.

```sh
go test -race ./...
go vet ./...
make release VERSION=1.6.0
(cd dist && sha256sum -c SHA256SUMS)

gh release create v1.6.0 \
  dist/sugyeol_1.6.0_* dist/SHA256SUMS \
  --repo ziozzang/sugyeol --target main --title "Sugyeol v1.6.0"
```

## 보안 경계

- 스크램블링은 난독화이며 기밀성을 제공하지 않습니다. 비밀 데이터에는 `--encrypt`를 사용합니다.
- ZIP/`.meta` 내장 공개키는 내부 무결성을 보일 뿐 현실 신원을 보장하지 않습니다. 별도로 받은 키를 `--pubkey/-k`로 고정합니다.
- 수결 명령을 통해 개인키가 `~/.sugyeol` 밖으로 내보내지지 않습니다.
- ZIP 압축은 스크램블링/암호화 뒤 적용되며 압축 설정은 manifest 서명 범위입니다.
- 컨테이너 서명은 검증된 OCI/docker 아카이브의 로컬 sidecar입니다. 레지스트리 artifact 게시와 키 폐기 인프라는 현재 범위 밖입니다.

## 라이선스와 이미지 출처

수결은 [MIT License](LICENSE)로 배포합니다.

README 이미지는 약 1400년경의 [조선 태종 수결](https://commons.wikimedia.org/wiki/File:Sign_of_Taejong_of_Joseon.jpg)입니다. Wikimedia Commons에서 [Public Domain](https://creativecommons.org/publicdomain/mark/1.0/)으로 표시한 자료입니다.
