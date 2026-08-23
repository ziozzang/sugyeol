package main

import (
	"os"
	"path/filepath"
)

// createWorkingTemp keeps large intermediate data on the filesystem selected by
// the caller's current directory instead of the system /tmp filesystem.
func createWorkingTemp(pattern string) (*os.File, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(cwd, "tmp")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	workDir, err := os.MkdirTemp(dir, "sugyeol-work-")
	if err != nil {
		_ = os.Remove(dir)
		return nil, err
	}
	file, err := os.CreateTemp(workDir, pattern)
	if err != nil {
		_ = os.Remove(workDir)
		_ = os.Remove(dir)
		return nil, err
	}
	return file, nil
}

func cleanupWorkingTemp(file *os.File) {
	if file == nil {
		return
	}
	name := file.Name()
	_ = file.Close()
	_ = os.Remove(name)
	workDir := filepath.Dir(name)
	_ = os.Remove(workDir)
	// Remove ./tmp only when Sugyeol left it empty. Existing user contents and
	// concurrent Sugyeol work therefore prevent removal and remain untouched.
	_ = os.Remove(filepath.Dir(workDir))
}
