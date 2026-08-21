package main

import (
	"fmt"
	"strconv"
	"strings"
)

func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("빈 크기")
	}
	i := 0
	for i < len(s) && ((s[i] >= '0' && s[i] <= '9') || s[i] == '.') {
		i++
	}
	n, err := strconv.ParseFloat(s[:i], 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("잘못된 크기 %q", s)
	}
	unit := strings.ToUpper(strings.TrimSpace(s[i:]))
	mul := float64(1)
	switch unit {
	case "":
		mul = 1000 * 1000
	case "B":
	case "K", "KB":
		mul = 1000
	case "M", "MB":
		mul = 1000 * 1000
	case "G", "GB":
		mul = 1000 * 1000 * 1000
	case "T", "TB":
		mul = 1000 * 1000 * 1000 * 1000
	case "KI", "KIB":
		mul = 1 << 10
	case "MI", "MIB":
		mul = 1 << 20
	case "GI", "GIB":
		mul = 1 << 30
	case "TI", "TIB":
		mul = 1 << 40
	default:
		return 0, fmt.Errorf("알 수 없는 크기 단위 %q", unit)
	}
	if n*mul > float64(^uint64(0)>>1) {
		return 0, fmt.Errorf("크기가 너무 큽니다")
	}
	return int64(n * mul), nil
}
