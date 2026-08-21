package main

import (
	"fmt"
	"os"
	"strings"
)

var currentLanguage = detectLanguage()

var messages = map[string]map[string]string{
	"en": {
		"command_required": "a command is required",
		"unknown_command":  "unknown command %q",
		"pack_usage":       "usage: sugyeol pack -size 10MiB -out backup <file|directory>",
		"verify_files":     "specify .zip parts to verify",
		"unpack_files":     "specify .zip parts to restore",
		"size_help":        "maximum part size (unitless values are MB; e.g. 10, 10MiB, 1GB)",
		"parts_help":       "split into exactly this many non-empty parts (mutually exclusive with size)",
		"out_help":         "output filename prefix",
		"scramble_help":    "enable reversible payload scrambling",
		"compression_help": "ZIP compression: none, fastest, default, highest, or 0..9",
		"restore_help":     "restore destination directory",
		"usage": `sugyeol - signed split ZIP creator/verifier/restorer

  Global UI: sugyeol [--lang en|ko] [--verbose|-v] [--debug] [--progress auto|always|never] <command>

  sugyeol [--lang en|ko] pack [-s 10MiB|-n 7] [-x=true|-e] [-c none|fastest|default|highest|0..9] -o backup <file|directory>
  sugyeol verify backup.part-*.zip
  sugyeol unpack -out <directory> backup.part-*.zip
  sugyeol sign -out source.meta <file|directory>
  sugyeol countersign -source <file|directory> -pubkey trusted.pem source.meta
  sugyeol verify -source <file|directory> source.meta
  sugyeol image pull [-S] -o image.oci.tgz <registry/repository:tag>
  sugyeol image sign <image.tar|image.tgz>
  sugyeol image verify <image.tar|image.tgz> [image.meta]
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
		"canceled":                 "sugyeol: canceled by user",
		"progress_tar":             "Creating source TAR",
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
		"command_required": "명령이 필요합니다",
		"unknown_command":  "알 수 없는 명령 %q",
		"pack_usage":       "사용법: sugyeol pack -size 10MiB -out backup <파일|디렉터리>",
		"verify_files":     "검사할 .zip 파트를 지정하세요",
		"unpack_files":     "복구할 .zip 파트를 지정하세요",
		"size_help":        "파트의 최대 크기 (단위 생략 시 MB; 예: 10, 10MiB, 1GB)",
		"parts_help":       "비어 있지 않은 파트를 정확히 이 개수로 생성 (size와 동시 사용 불가)",
		"out_help":         "출력 파일 접두사",
		"scramble_help":    "가역 payload 스크램블링 사용",
		"compression_help": "ZIP 압축: none, fastest, default, highest 또는 0..9",
		"restore_help":     "복구 대상 디렉터리",
		"usage": `sugyeol - 서명된 분할 ZIP 생성/검사/복구

  전역 UI: sugyeol [--lang en|ko] [--verbose|-v] [--debug] [--progress auto|always|never] <명령>

  sugyeol [--lang en|ko] pack [-s 10MiB|-n 7] [-x=true|-e] [-c none|fastest|default|highest|0..9] -o backup <파일|디렉터리>
  sugyeol verify backup.part-*.zip
  sugyeol unpack -out <디렉터리> backup.part-*.zip
  sugyeol sign -out source.meta <파일|디렉터리>
  sugyeol countersign -source <파일|디렉터리> -pubkey trusted.pem source.meta
  sugyeol verify -source <파일|디렉터리> source.meta
  sugyeol image pull [-S] -o image.oci.tgz <registry/repository:tag>
  sugyeol image sign <image.tar|image.tgz>
  sugyeol image verify <image.tar|image.tgz> [image.meta]
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
		"canceled":                 "sugyeol: 사용자 요청으로 취소했습니다",
		"progress_tar":             "원본 TAR 생성",
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
