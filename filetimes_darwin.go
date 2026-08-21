//go:build darwin

package main

import (
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func platformFileTimes(_ string, info os.FileInfo) (time.Time, time.Time, bool, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return time.Time{}, time.Time{}, false, nil
	}
	access := time.Unix(stat.Atimespec.Sec, stat.Atimespec.Nsec)
	birth := time.Unix(stat.Birthtimespec.Sec, stat.Birthtimespec.Nsec)
	hasBirth := stat.Birthtimespec.Sec != 0 || stat.Birthtimespec.Nsec != 0
	return access, birth, hasBirth, nil
}

func setPlatformBirthTime(path string, value time.Time) (bool, error) {
	ts := unix.NsecToTimespec(value.UnixNano())
	buffer := unsafe.Slice((*byte)(unsafe.Pointer(&ts)), int(unsafe.Sizeof(ts)))
	attrs := unix.Attrlist{Bitmapcount: unix.ATTR_BIT_MAP_COUNT, Commonattr: unix.ATTR_CMN_CRTIME}
	if err := unix.Setattrlist(path, &attrs, buffer, unix.FSOPT_NOFOLLOW); err != nil {
		return false, err
	}
	return true, nil
}
