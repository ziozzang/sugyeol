package main

import (
	"archive/tar"
	"fmt"
	"os"
	"runtime"
	"time"
)

const sugyeolBirthTimePAX = "SUGYEOL.birthtime"

type restoredMetadata struct {
	path       string
	mode       os.FileMode
	modTime    time.Time
	accessTime time.Time
	birthTime  time.Time
	hasBirth   bool
}

func addFileTimesToHeader(path string, info os.FileInfo, h *tar.Header) error {
	accessTime, birthTime, hasBirth, err := platformFileTimes(path, info)
	if err != nil {
		return err
	}
	h.Format = tar.FormatPAX
	if !accessTime.IsZero() {
		h.AccessTime = accessTime
	}
	if hasBirth {
		if h.PAXRecords == nil {
			h.PAXRecords = make(map[string]string)
		}
		h.PAXRecords[sugyeolBirthTimePAX] = birthTime.UTC().Format(time.RFC3339Nano)
	}
	return nil
}

func metadataFromHeader(path string, h *tar.Header) (restoredMetadata, error) {
	m := restoredMetadata{path: path, mode: os.FileMode(h.Mode) & os.ModePerm, modTime: h.ModTime, accessTime: h.AccessTime}
	if m.accessTime.IsZero() {
		m.accessTime = m.modTime
	}
	if encoded := h.PAXRecords[sugyeolBirthTimePAX]; encoded != "" {
		birth, err := time.Parse(time.RFC3339Nano, encoded)
		if err != nil {
			return restoredMetadata{}, fmt.Errorf("invalid archived creation time for %q: %w", h.Name, err)
		}
		m.birthTime, m.hasBirth = birth, true
	}
	return m, nil
}

func applyRestoredMetadata(m restoredMetadata) error {
	if err := os.Chmod(m.path, m.mode); err != nil {
		return fmt.Errorf("restore mode for %s: %w", m.path, err)
	}
	if !m.modTime.IsZero() {
		if err := os.Chtimes(m.path, m.accessTime, m.modTime); err != nil {
			return fmt.Errorf("restore timestamps for %s: %w", m.path, err)
		}
	}
	if m.hasBirth {
		applied, err := setPlatformBirthTime(m.path, m.birthTime)
		if err != nil {
			return fmt.Errorf("restore creation time for %s: %w", m.path, err)
		}
		if !applied {
			uiVerbosef("creation time retained in archive but cannot be applied on %s: %s", runtime.GOOS, m.path)
		}
	}
	uiVerbosef("restored metadata: %s (mode=%04o, mtime=%s, atime=%s)", m.path, m.mode.Perm(), m.modTime.UTC().Format(time.RFC3339Nano), m.accessTime.UTC().Format(time.RFC3339Nano))
	return nil
}
