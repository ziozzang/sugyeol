//go:build windows

package main

import (
	"os"
	"syscall"
	"time"
)

func platformFileTimes(_ string, info os.FileInfo) (time.Time, time.Time, bool, error) {
	stat, ok := info.Sys().(*syscall.Win32FileAttributeData)
	if !ok {
		return time.Time{}, time.Time{}, false, nil
	}
	access := time.Unix(0, stat.LastAccessTime.Nanoseconds())
	birth := time.Unix(0, stat.CreationTime.Nanoseconds())
	hasBirth := stat.CreationTime.HighDateTime != 0 || stat.CreationTime.LowDateTime != 0
	return access, birth, hasBirth, nil
}

func setPlatformBirthTime(path string, value time.Time) (bool, error) {
	pointer, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return false, err
	}
	handle, err := syscall.CreateFile(pointer, syscall.FILE_WRITE_ATTRIBUTES,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil,
		syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return false, err
	}
	defer syscall.CloseHandle(handle)
	creation := syscall.NsecToFiletime(value.UnixNano())
	if err := syscall.SetFileTime(handle, &creation, nil, nil); err != nil {
		return false, err
	}
	return true, nil
}
