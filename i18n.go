package main

import (
	"fmt"
	"os"
	"strings"
)

var currentLanguage = detectLanguage()

var messages = map[string]map[string]string{
	"en": {
		"about": `SUGYEOL(1)                   User Commands                  SUGYEOL(1)

NAME
  Sugyeol %s - signed packaging, cumulative signatures, container archives,
  and SPDX SBOM generation

SYNOPSIS
  sugyeol [--lang en|ko] [--verbose|-v] [--debug]
           [--progress auto|always|never] <command> [options] [arguments]
  sugyeol                         Show this concise manual.

DESCRIPTION
  Sugyeol signs files and directories directly or packages them as bounded,
  signed split ZIP files. It also downloads, retags, signs, verifies, and
  inventories OCI/Docker container archives without requiring Docker.

  Author:  Jioh Jung <jioh@jung.net>
  GitHub:  https://github.com/ziozzang/sugyeol
  License: MIT

COMMANDS
  key init       Create the local Ed25519 identity and private key.
  key            Export the public key; the private key stays under ~/.sugyeol.
  pack           Package a file/directory into signed size- or count-split ZIP parts.
  unpack         Verify and restore complete package sets from prefixes, fragments, globs, or directories.
  verify         Verify split ZIPs, or verify a file/directory against detached .meta signatures.
  sign           Create SHA-256/Ed25519 detached .meta signatures without packaging.
  countersign    Append a signature only after validating the subject and every prior signature.
  image pull     Download from a registry without Docker and create a Docker-loadable OCI tar/tgz.
  image sign     Sign a local OCI/docker-save archive; image countersign appends a validated signature.
  image verify   Verify the image graph, archive hash, signature chain, signer, and pinned keys.
  image sbom     Generate native SPDX 2.3 package/file SBOMs; add verify to validate binding/signatures.
  update         Check for or install a signed GitHub release update.
  version        Print only the version. about/info prints this guide; help prints full syntax.

QUICK START
  sugyeol key init -n "Jane Doe" -e jane@example.com
  sugyeol pack -s 1900 -o backup ./source
  sugyeol verify backup_part-*.zip
  sugyeol unpack -o ./restored backup_part-000001
  sugyeol sign -o source.meta ./source
  sugyeol verify -s ./source source.meta
  sugyeol image pull -S -B -t alpine:260904 alpine:latest
  sugyeol image verify -k signer.pem alpine-260904.oci.tar
  sugyeol image sbom verify alpine-260904.oci.tar alpine-260904.spdx.json

GLOBAL OPTIONS
  --lang en|ko  --verbose|-v  --debug  --progress auto|always|never  --no-progress

FILES
  ~/.sugyeol/       Local identity and Ed25519 private key (mode 0600).
  ./tmp/            Same-filesystem temporary workspace, removed after use.
  *.meta            Detached signature chain containing signatures and public keys.
  *_part-*.zip      Signed split-package parts with embedded hashes/key/signature.

SECURITY
  Pin expected signer keys with -k/--pubkey. A valid embedded signature proves
  integrity but does not independently establish the signer's identity.

EXIT STATUS
  0  Success.   1  Validation/operation failure.   130  Canceled by Ctrl+C.

SEE ALSO
  sugyeol help      Complete command syntax.
  README.md         Detailed workflows, formats, security model, and examples.
  https://github.com/ziozzang/sugyeol
`,
		"command_required":             "a command is required",
		"unknown_command":              "unknown command %q",
		"pack_usage":                   "usage: sugyeol pack -size 10MiB -out backup <file|directory>",
		"verify_files":                 "specify .zip parts to verify",
		"unpack_files":                 "specify package prefixes, partial ZIP names, glob patterns, or directories to restore",
		"unpack_no_match":              "no package parts match %q",
		"unpack_overwrite_prompt":      "matched packages restore the same root(s): %s; overwrite with the later package? [y/N] ",
		"unpack_overwrite_declined":    "restore canceled because overwrite was not approved",
		"unpack_overwrite_nonterminal": "matched packages restore the same root(s): %s; use --overwrite (-y) in non-interactive mode",
		"size_help":                    "maximum part size (unitless values are MB; e.g. 10, 10MiB, 1GB)",
		"parts_help":                   "split into exactly this many non-empty parts (mutually exclusive with size)",
		"out_help":                     "output filename prefix",
		"scramble_help":                "enable reversible payload scrambling",
		"compression_help":             "ZIP compression: none, fastest, default, highest, or 0..9",
		"restore_help":                 "restore destination directory",
		"usage": `sugyeol - signed split ZIP creator/verifier/restorer

  Global UI: sugyeol [--lang en|ko] [--verbose|-v] [--debug] [--progress auto|always|never] <command>

  sugyeol [--lang en|ko] pack [-s 10MiB|-n 7] [-x=true|-e] [-c none|fastest|default|highest|0..9] -o backup <file|directory>
  sugyeol verify backup_part-*.zip
  sugyeol unpack [-o <directory>] [-y] <prefix|partial-part|part.zip|glob|directory> [more...]
  sugyeol sign -out source.meta <file|directory>
  sugyeol countersign -source <file|directory> -pubkey trusted.pem source.meta
  sugyeol verify -source <file|directory> source.meta
  sugyeol image pull [-S] [-g|-B] [-t imported/name:tag] [-o image.oci.tgz] <registry/repository:tag>
  sugyeol image sbom [-S] [-p linux/amd64|-a] -o image.spdx.json|directory <image.tar|image.tgz>
  sugyeol image sbom verify <image.tar|image.tgz> <image.spdx.json> [image.spdx.json.meta]
  sugyeol image sign <image.tar|image.tgz>
  sugyeol image verify <image.tar|image.tgz> [image.meta]
  sugyeol about
  sugyeol key init --name <name> --email <email>
  sugyeol key [-out public_key.pem]
  sugyeol update [--check]`,
		"created":                  "created %s (%d bytes)\n",
		"verified":                 "verified %s (part %d/%d)\n",
		"restored":                 "restored %s into %s\n",
		"update_current":           "current: %s\nlatest:  %s\n",
		"update_available":         "a newer version is available: %s -> %s\n",
		"update_latest":            "you are on the latest version\n",
		"update_newer":             "your version is newer than the published release (%s)\n",
		"update_downloading":       "downloading %s (%s)...\n",
		"updated":                  "updated %s: %s -> %s\n",
		"update_notice":            "sugyeol %s is available (you have %s). Run 'sugyeol update' to upgrade.",
		"signed":                   "signed %s -> %s\n",
		"public_key":               "public key: %s\n",
		"fingerprint":              "fingerprint: %s\n",
		"public_key_pem":           "public key PEM: %s\n",
		"signature_ok":             "signature OK: %s\n",
		"signer":                   "signer: %s\n",
		"signed_at":                "signed at: %s\n",
		"unpinned_warning":         "warning: no trusted public key was pinned; integrity is proven, signer identity is not",
		"signed_subject":           "signed subject: %s (%d manifest entries, %d signatures)\n",
		"container_signed_subject": "signed image graph: %d root descriptors, %d references, %d signatures\n",
		"signature_detail_header":  "\nsignature %d/%d\n",
		"signature_crypto_status":  "  cryptographic status: %s\n",
		"signature_valid":          "valid",
		"signature_trust":          "  signer trust: %s\n",
		"signature_trust_pinned":   "trusted (matched a pinned public key)",
		"signature_trust_unpinned": "embedded key only (identity is not independently trusted)",
		"signature_trust_chain":    "chain-valid, but this signer is not directly pinned",
		"signature_signer":         "  signer: %s\n",
		"signature_role":           "  role/label: %s\n",
		"signature_role_none":      "(none)",
		"signature_signed_at":      "  signed at: %s\n",
		"signature_algorithm":      "  algorithm: %s\n",
		"signature_public_key":     "  public key: %s\n",
		"signature_fingerprint":    "  fingerprint: %s\n",
		"signature_manifest_sha":   "  manifest SHA-256: %s\n",
		"signature_previous_sha":   "  previous record SHA-256: %s\n",
		"signature_record_sha":     "  record SHA-256: %s\n",
		"signature_salt":           "  signed salt: %s\n",
		"signature_value":          "  Ed25519 signature: %s\n",
		"signature_genesis":        "(genesis signature)",
		"package_signature_ok":     "package signature OK: %s\n",
		"package_subject":          "package set: %s; %d parts; %s TAR payload\n",
		"package_protection":       "protection: scramble=%s; encryption=%s; compression=%s\n",
		"package_signatures_valid": "%d/%d part signatures valid",
		"signed_at_range":          "  signed from: %s\n  signed through: %s\n",
		"package_part_detail":      "  part %d/%d: signed_at=%s salt=%s payload_sha256=%s stored_sha256=%s\n",
		"canceled":                 "sugyeol: canceled by user",
		"progress_tar":             "Creating source TAR",
		"progress_scan_source":     "Scanning source files",
		"progress_pack":            "Processing package payload",
		"progress_write_part":      "Writing ZIP part %d/%d",
		"progress_compress_part":   "Compressing ZIP part %d/%d",
		"progress_verify_part":     "Verifying ZIP part %d/%d",
		"progress_restore":         "Restoring package payload",
		"progress_extract":         "Extracting files",
		"progress_hash_source":     "Hashing source content",
		"progress_inspect_image":   "Inspecting container archive",
		"progress_resolve_image":   "Resolving image manifests",
		"progress_pull_blobs":      "Downloading image content",
		"progress_sbom":            "Generating SPDX SBOM",
		"progress_release_lookup":  "Checking GitHub release",
		"progress_checksums":       "Fetching release checksums",
		"progress_update_download": "Downloading update",
		"progress_state_done":      "done",
		"progress_state_failed":    "failed",
		"progress_state_canceled":  "canceled",
		"progress_summary":         "%s: %s (%s in %s, %s/s average)\n",
		"progress_working":         "%s: working (%s)\n",
	},
	"ko": {
		"about": `수결(1)                       사용자 명령                       수결(1)

이름
  수결(Sugyeol) %s - 서명 패키징, 누적 서명, 컨테이너 아카이브와
  SPDX SBOM 생성 도구

사용법
  sugyeol [--lang en|ko] [--verbose|-v] [--debug]
           [--progress auto|always|never] <명령> [옵션] [인자]
  sugyeol                         이 축약 매뉴얼을 표시합니다.

설명
  파일과 디렉터리를 직접 서명하거나 지정 크기를 넘지 않는 서명된 분할
  ZIP으로 패키징합니다. Docker 없이 OCI/Docker 컨테이너 아카이브를 받고,
  태그 변경, 서명, 검증과 package/file 수준 inventory를 수행할 수 있습니다.

  작성자:  Jioh Jung <jioh@jung.net>
  GitHub:  https://github.com/ziozzang/sugyeol
  라이선스: MIT

명령 목록:
  key init       로컬 Ed25519 신원과 개인키를 생성합니다.
  key            공개키를 내보냅니다. 개인키는 ~/.sugyeol 밖으로 복사하지 않습니다.
  pack           파일/디렉터리를 서명하고 크기 또는 개수 기준 분할 ZIP으로 패킹합니다.
  unpack         접두사·파일명 일부·glob·디렉터리에서 전체 package set을 찾아 검증·복구합니다.
  verify         분할 ZIP을 검증하거나 detached .meta와 원본 파일/디렉터리를 검증합니다.
  sign           패킹하지 않고 SHA-256/Ed25519 detached .meta 서명을 만듭니다.
  countersign    원본과 이전 서명 체인을 모두 검증한 뒤 누적 서명을 추가합니다.
  image pull     Docker 없이 registry에서 받아 Docker-load 가능한 OCI tar/tgz를 만듭니다.
  image sign     로컬 OCI/docker-save archive를 서명하며 image countersign으로 검증 후 누적 서명합니다.
  image verify   image graph, archive hash, 서명 체인, signer와 고정 공개키를 검증합니다.
  image sbom     네이티브 SPDX 2.3 package/file SBOM을 만들며 verify로 결합·서명을 검사합니다.
  update         서명된 GitHub release 업데이트를 확인하거나 설치합니다.
  version        버전만 출력합니다. about/info는 이 안내, help는 전체 문법을 출력합니다.

빠른 시작:
  sugyeol key init -n "홍길동" -e hong@example.com
  sugyeol pack -s 1900 -o backup ./source
  sugyeol verify backup_part-*.zip
  sugyeol unpack -o ./restored backup_part-000001
  sugyeol sign -o source.meta ./source
  sugyeol verify -s ./source source.meta
  sugyeol image pull -S -B -t alpine:260904 alpine:latest
  sugyeol image verify -k signer.pem alpine-260904.oci.tar
  sugyeol image sbom verify alpine-260904.oci.tar alpine-260904.spdx.json

전역 UI:
  --lang en|ko  --verbose|-v  --debug  --progress auto|always|never  --no-progress

파일
  ~/.sugyeol/       로컬 identity와 Ed25519 개인키(mode 0600).
  ./tmp/            같은 파일시스템의 임시 작업공간. 작업 후 제거합니다.
  *.meta            서명, 공개키와 누적 연결을 담은 detached 서명 체인.
  *_part-*.zip      hash/key/signature를 내부에 담은 서명 분할 패키지.

보안
  기대한 signer 공개키는 -k/--pubkey로 고정하세요. 내장키 서명만으로도
  무결성은 증명하지만 signer의 실제 신원을 독립적으로 보증하지는 않습니다.

종료 상태
  0  성공.   1  검증/작업 실패.   130  Ctrl+C로 취소.

함께 보기
  sugyeol help      전체 명령 문법.
  README_KO.md      상세 workflow, format, 보안 모델과 예시.
  https://github.com/ziozzang/sugyeol
`,
		"command_required":             "명령이 필요합니다",
		"unknown_command":              "알 수 없는 명령 %q",
		"pack_usage":                   "사용법: sugyeol pack -size 10MiB -out backup <파일|디렉터리>",
		"verify_files":                 "검사할 .zip 파트를 지정하세요",
		"unpack_files":                 "복구할 패키지 접두사, ZIP 파일명 일부, glob 패턴 또는 디렉터리를 지정하세요",
		"unpack_no_match":              "%q에 일치하는 패키지 파트가 없습니다",
		"unpack_overwrite_prompt":      "매칭된 패키지의 복구 루트가 겹칩니다: %s; 뒤 패키지로 덮어쓸까요? [y/N] ",
		"unpack_overwrite_declined":    "덮어쓰기가 승인되지 않아 복구를 취소했습니다",
		"unpack_overwrite_nonterminal": "매칭된 패키지의 복구 루트가 겹칩니다: %s; 비대화형 실행에서는 --overwrite (-y)를 사용하세요",
		"size_help":                    "파트의 최대 크기 (단위 생략 시 MB; 예: 10, 10MiB, 1GB)",
		"parts_help":                   "비어 있지 않은 파트를 정확히 이 개수로 생성 (size와 동시 사용 불가)",
		"out_help":                     "출력 파일 접두사",
		"scramble_help":                "가역 payload 스크램블링 사용",
		"compression_help":             "ZIP 압축: none, fastest, default, highest 또는 0..9",
		"restore_help":                 "복구 대상 디렉터리",
		"usage": `sugyeol - 서명된 분할 ZIP 생성/검사/복구

  전역 UI: sugyeol [--lang en|ko] [--verbose|-v] [--debug] [--progress auto|always|never] <명령>

  sugyeol [--lang en|ko] pack [-s 10MiB|-n 7] [-x=true|-e] [-c none|fastest|default|highest|0..9] -o backup <파일|디렉터리>
  sugyeol verify backup_part-*.zip
  sugyeol unpack [-o <디렉터리>] [-y] <접두사|파트명-일부|파트.zip|glob|디렉터리> [추가...]
  sugyeol sign -out source.meta <파일|디렉터리>
  sugyeol countersign -source <파일|디렉터리> -pubkey trusted.pem source.meta
  sugyeol verify -source <파일|디렉터리> source.meta
  sugyeol image pull [-S] [-g|-B] [-t 가져올/이름:태그] [-o image.oci.tgz] <registry/repository:tag>
  sugyeol image sbom [-S] [-p linux/amd64|-a] -o image.spdx.json|디렉터리 <image.tar|image.tgz>
  sugyeol image sbom verify <image.tar|image.tgz> <image.spdx.json> [image.spdx.json.meta]
  sugyeol image sign <image.tar|image.tgz>
  sugyeol image verify <image.tar|image.tgz> [image.meta]
  sugyeol about
  sugyeol key init --name <이름> --email <이메일>
  sugyeol key [-out public_key.pem]
  sugyeol update [--check]`,
		"created":                  "%s 생성 (%d 바이트)\n",
		"verified":                 "%s 검증 완료 (파트 %d/%d)\n",
		"restored":                 "%s을(를) %s에 복구했습니다\n",
		"update_current":           "현재: %s\n최신: %s\n",
		"update_available":         "새 버전이 있습니다: %s -> %s\n",
		"update_latest":            "최신 버전을 사용 중입니다\n",
		"update_newer":             "현재 버전이 공개 릴리스(%s)보다 새 버전입니다\n",
		"update_downloading":       "%s (%s) 다운로드 중...\n",
		"updated":                  "%s 업데이트 완료: %s -> %s\n",
		"update_notice":            "sugyeol %s 버전이 있습니다(현재 %s). 'sugyeol update'로 업데이트하세요.",
		"signed":                   "%s 서명 완료 -> %s\n",
		"public_key":               "공개키: %s\n",
		"fingerprint":              "지문: %s\n",
		"public_key_pem":           "공개키 PEM: %s\n",
		"signature_ok":             "서명 검증 완료: %s\n",
		"signer":                   "서명자: %s\n",
		"signed_at":                "서명 시각: %s\n",
		"unpinned_warning":         "경고: 신뢰된 공개키를 지정하지 않아 무결성만 증명되며 서명자 신원은 증명되지 않습니다",
		"signed_subject":           "서명 대상: %s (manifest 항목 %d개, 서명 %d개)\n",
		"container_signed_subject": "서명된 이미지 그래프: root descriptor %d개, reference %d개, 서명 %d개\n",
		"signature_detail_header":  "\n서명 %d/%d\n",
		"signature_crypto_status":  "  암호학적 상태: %s\n",
		"signature_valid":          "유효",
		"signature_trust":          "  서명자 신뢰: %s\n",
		"signature_trust_pinned":   "신뢰함(고정한 공개키와 일치)",
		"signature_trust_unpinned": "내장 공개키만 확인(신원을 독립적으로 신뢰하지 않음)",
		"signature_trust_chain":    "체인은 유효하지만 이 서명자를 직접 고정하지 않음",
		"signature_signer":         "  서명자: %s\n",
		"signature_role":           "  역할/라벨: %s\n",
		"signature_role_none":      "(없음)",
		"signature_signed_at":      "  서명 시각: %s\n",
		"signature_algorithm":      "  알고리즘: %s\n",
		"signature_public_key":     "  공개키: %s\n",
		"signature_fingerprint":    "  지문: %s\n",
		"signature_manifest_sha":   "  manifest SHA-256: %s\n",
		"signature_previous_sha":   "  이전 레코드 SHA-256: %s\n",
		"signature_record_sha":     "  레코드 SHA-256: %s\n",
		"signature_salt":           "  서명 salt: %s\n",
		"signature_value":          "  Ed25519 서명값: %s\n",
		"signature_genesis":        "(최초 서명)",
		"package_signature_ok":     "패키지 서명 검증 완료: %s\n",
		"package_subject":          "패키지 세트: %s; 파트 %d개; TAR payload %s\n",
		"package_protection":       "보호 방식: scramble=%s; encryption=%s; compression=%s\n",
		"package_signatures_valid": "파트 서명 %d/%d개 유효",
		"signed_at_range":          "  최초 서명 시각: %s\n  마지막 서명 시각: %s\n",
		"package_part_detail":      "  파트 %d/%d: signed_at=%s salt=%s payload_sha256=%s stored_sha256=%s\n",
		"canceled":                 "sugyeol: 사용자 요청으로 취소했습니다",
		"progress_tar":             "원본 TAR 생성",
		"progress_scan_source":     "원본 파일 탐색",
		"progress_pack":            "패키지 payload 처리",
		"progress_write_part":      "ZIP 파트 %d/%d 기록",
		"progress_compress_part":   "ZIP 파트 %d/%d 압축",
		"progress_verify_part":     "ZIP 파트 %d/%d 검증",
		"progress_restore":         "패키지 payload 복구",
		"progress_extract":         "파일 추출",
		"progress_hash_source":     "원본 내용 해시 계산",
		"progress_inspect_image":   "컨테이너 아카이브 검사",
		"progress_resolve_image":   "이미지 manifest 확인",
		"progress_pull_blobs":      "이미지 내용 다운로드",
		"progress_sbom":            "SPDX SBOM 생성",
		"progress_release_lookup":  "GitHub 릴리스 확인",
		"progress_checksums":       "릴리스 체크섬 확인",
		"progress_update_download": "업데이트 다운로드",
		"progress_state_done":      "완료",
		"progress_state_failed":    "실패",
		"progress_state_canceled":  "취소",
		"progress_summary":         "%s: %s (%s, %s, 평균 %s/s)\n",
		"progress_working":         "%s: 작업 중 (%s)\n",
	},
}

func detectLanguage() string {
	for _, name := range []string{"SUGYEOL_LANG", "LC_ALL", "LC_MESSAGES", "LANG"} {
		v := strings.ToLower(os.Getenv(name))
		if strings.HasPrefix(v, "ko") {
			return "ko"
		}
		if strings.HasPrefix(v, "en") {
			return "en"
		}
	}
	return "en"
}

func setLanguage(lang string) {
	lang = strings.ToLower(strings.TrimSpace(lang))
	if strings.HasPrefix(lang, "ko") {
		currentLanguage = "ko"
	} else {
		currentLanguage = "en"
	}
}

func parseLanguageArg(args []string) []string {
	if len(args) >= 2 && args[0] == "--lang" {
		setLanguage(args[1])
		return args[2:]
	}
	if len(args) >= 1 && strings.HasPrefix(args[0], "--lang=") {
		setLanguage(strings.TrimPrefix(args[0], "--lang="))
		return args[1:]
	}
	return args
}

func tr(key string, args ...any) string {
	s := messages[currentLanguage][key]
	if s == "" {
		s = messages["en"][key]
	}
	if len(args) == 0 {
		return s
	}
	return fmt.Sprintf(s, args...)
}
