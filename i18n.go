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
		"out_help":         "output filename prefix",
		"scramble_help":    "enable reversible payload scrambling",
		"restore_help":     "restore destination directory",
		"usage": `sugyeol - signed split ZIP creator/verifier/restorer

  sugyeol [--lang en|ko] pack -size 10MiB [-scramble=true|-encrypt] -out backup <file|directory>
  sugyeol verify backup.part-*.zip
  sugyeol unpack -out <directory> backup.part-*.zip
  sugyeol sign -out source.meta <file|directory>
  sugyeol countersign -source <file|directory> -pubkey trusted.pem source.meta
  sugyeol verify -source <file|directory> source.meta
  sugyeol image sign <registry/repository:tag>
  sugyeol image verify <image.meta>
  sugyeol key init --name <name> --email <email>
  sugyeol key [-out public_key.pem]
  sugyeol update [--check]`,
		"created":            "created %s (%d bytes)\n",
		"verified":           "verified %s (part %d/%d)\n",
		"restored":           "restored %s into %s\n",
		"update_current":     "current: %s\nlatest:  %s\n",
		"update_available":   "a newer version is available: %s -> %s\n",
		"update_latest":      "you are on the latest version\n",
		"update_newer":       "your version is newer than the published release (%s)\n",
		"update_downloading": "downloading %s (%s)...\n",
		"updated":            "updated %s: %s -> %s\n",
		"update_notice":      "sugyeol %s is available (you have %s). Run 'sugyeol update' to upgrade.",
		"signed":             "signed %s -> %s\n",
		"public_key":         "public key: %s\n",
		"fingerprint":        "fingerprint: %s\n",
		"public_key_pem":     "public key PEM: %s\n",
		"signature_ok":       "signature OK: %s\n",
		"signer":             "signer: %s\n",
		"signed_at":          "signed at: %s\n",
		"unpinned_warning":   "warning: no trusted public key was pinned; integrity is proven, signer identity is not",
	},
	"ko": {
		"command_required": "명령이 필요합니다",
		"unknown_command":  "알 수 없는 명령 %q",
		"pack_usage":       "사용법: sugyeol pack -size 10MiB -out backup <파일|디렉터리>",
		"verify_files":     "검사할 .zip 파트를 지정하세요",
		"unpack_files":     "복구할 .zip 파트를 지정하세요",
		"size_help":        "파트의 최대 크기 (단위 생략 시 MB; 예: 10, 10MiB, 1GB)",
		"out_help":         "출력 파일 접두사",
		"scramble_help":    "가역 payload 스크램블링 사용",
		"restore_help":     "복구 대상 디렉터리",
		"usage": `sugyeol - 서명된 분할 ZIP 생성/검사/복구

  sugyeol [--lang en|ko] pack -size 10MiB [-scramble=true|-encrypt] -out backup <파일|디렉터리>
  sugyeol verify backup.part-*.zip
  sugyeol unpack -out <디렉터리> backup.part-*.zip
  sugyeol sign -out source.meta <파일|디렉터리>
  sugyeol countersign -source <파일|디렉터리> -pubkey trusted.pem source.meta
  sugyeol verify -source <파일|디렉터리> source.meta
  sugyeol image sign <registry/repository:tag>
  sugyeol image verify <image.meta>
  sugyeol key init --name <이름> --email <이메일>
  sugyeol key [-out public_key.pem]
  sugyeol update [--check]`,
		"created":            "%s 생성 (%d 바이트)\n",
		"verified":           "%s 검증 완료 (파트 %d/%d)\n",
		"restored":           "%s을(를) %s에 복구했습니다\n",
		"update_current":     "현재: %s\n최신: %s\n",
		"update_available":   "새 버전이 있습니다: %s -> %s\n",
		"update_latest":      "최신 버전을 사용 중입니다\n",
		"update_newer":       "현재 버전이 공개 릴리스(%s)보다 새 버전입니다\n",
		"update_downloading": "%s (%s) 다운로드 중...\n",
		"updated":            "%s 업데이트 완료: %s -> %s\n",
		"update_notice":      "sugyeol %s 버전이 있습니다(현재 %s). 'sugyeol update'로 업데이트하세요.",
		"signed":             "%s 서명 완료 -> %s\n",
		"public_key":         "공개키: %s\n",
		"fingerprint":        "지문: %s\n",
		"public_key_pem":     "공개키 PEM: %s\n",
		"signature_ok":       "서명 검증 완료: %s\n",
		"signer":             "서명자: %s\n",
		"signed_at":          "서명 시각: %s\n",
		"unpinned_warning":   "경고: 신뢰된 공개키를 지정하지 않아 무결성만 증명되며 서명자 신원은 증명되지 않습니다",
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
