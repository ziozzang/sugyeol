//go:build !linux && !darwin && !windows

package main

import (
	"os"
	"time"
)

func platformFileTimes(_ string, _ os.FileInfo) (time.Time, time.Time, bool, error) {
	return time.Time{}, time.Time{}, false, nil
}

func setPlatformBirthTime(_ string, _ time.Time) (bool, error) {
	return false, nil
}
