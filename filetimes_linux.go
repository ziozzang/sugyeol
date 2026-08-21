//go:build linux

package main

import (
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func platformFileTimes(path string, info os.FileInfo) (time.Time, time.Time, bool, error) {
	var stat unix.Statx_t
	err := unix.Statx(unix.AT_FDCWD, path, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_BASIC_STATS|unix.STATX_BTIME, &stat)
	if err == nil {
		access := time.Unix(stat.Atime.Sec, int64(stat.Atime.Nsec))
		if stat.Mask&unix.STATX_BTIME == 0 {
			return access, time.Time{}, false, nil
		}
		birth := time.Unix(stat.Btime.Sec, int64(stat.Btime.Nsec))
		return access, birth, true, nil
	}
	// statx may be unavailable on an older kernel or filesystem. Access time is
	// still available through the FileInfo supplied by Walk; creation time is not.
	if legacy, ok := info.Sys().(*syscall.Stat_t); ok {
		return time.Unix(legacy.Atim.Sec, legacy.Atim.Nsec), time.Time{}, false, nil
	}
	return time.Time{}, time.Time{}, false, nil
}

func setPlatformBirthTime(_ string, _ time.Time) (bool, error) {
	// Linux statx can read btime, but Linux filesystems do not expose an API to set it.
	return false, nil
}
