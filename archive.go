package main

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func makeTar(source string) (*os.File, int64, string, error) {
	abs, err := filepath.Abs(source)
	if err != nil {
		return nil, 0, "", err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return nil, 0, "", err
	}
	tmp, err := os.CreateTemp("", "sugyeol-source-*.tar")
	if err != nil {
		return nil, 0, "", err
	}
	ok := false
	defer func() {
		if !ok {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	tw := tar.NewWriter(tmp)
	rootParent := filepath.Dir(abs)
	total, err := regularFileBytes(abs)
	if err != nil {
		return nil, 0, "", err
	}
	progress := newProgress(tr("progress_tar"), total)
	err = filepath.Walk(abs, func(path string, fi os.FileInfo, walkErr error) error {
		if err := checkCanceled(); err != nil {
			return err
		}
		if walkErr != nil {
			return walkErr
		}
		if !fi.IsDir() && !fi.Mode().IsRegular() {
			return fmt.Errorf("지원하지 않는 입력 항목(일반 파일/디렉터리만 허용): %s", path)
		}
		rel, err := filepath.Rel(rootParent, path)
		if err != nil {
			return err
		}
		h, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			return err
		}
		h.Name = filepath.ToSlash(rel)
		if fi.IsDir() && !strings.HasSuffix(h.Name, "/") {
			h.Name += "/"
		}
		if err := addFileTimesToHeader(path, fi, h); err != nil {
			return err
		}
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if fi.Mode().IsRegular() {
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			uiVerbosef("TAR: %s (%s)", filepath.ToSlash(rel), humanSize(fi.Size()))
			_, copyErr := io.Copy(tw, progress.Reader(f))
			closeErr := f.Close()
			if copyErr != nil {
				return copyErr
			}
			return closeErr
		}
		return nil
	})
	if err == nil {
		err = tw.Close()
	}
	progress.Finish(err)
	if err != nil {
		return nil, 0, "", err
	}
	sz, err := tmp.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, 0, "", err
	}
	if _, err = tmp.Seek(0, io.SeekStart); err != nil {
		return nil, 0, "", err
	}
	ok = true
	return tmp, sz, info.Name(), nil
}

func regularFileBytes(root string) (int64, error) {
	var total int64
	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := checkCanceled(); err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			if info.Size() > 0 && total > (1<<63-1)-info.Size() {
				return fmt.Errorf("input is too large")
			}
			total += info.Size()
		}
		return nil
	})
	return total, err
}

func extractTar(r io.Reader, dest string) error {
	absDest, err := filepath.Abs(dest)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(absDest, 0755); err != nil {
		return err
	}
	tr := tar.NewReader(r)
	directories := make([]restoredMetadata, 0)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("TAR 읽기: %w", err)
		}
		clean := filepath.Clean(filepath.FromSlash(h.Name))
		if clean == "." || filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return fmt.Errorf("안전하지 않은 TAR 경로 %q", h.Name)
		}
		target := filepath.Join(absDest, clean)
		if target != absDest && !strings.HasPrefix(target, absDest+string(filepath.Separator)) {
			return fmt.Errorf("대상 밖 경로 %q", h.Name)
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
			metadata, err := metadataFromHeader(target, h)
			if err != nil {
				return err
			}
			directories = append(directories, metadata)
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(h.Mode)&0777)
			if err != nil {
				return err
			}
			_, copyErr := io.CopyN(f, tr, h.Size)
			closeErr := f.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
			metadata, err := metadataFromHeader(target, h)
			if err != nil {
				return err
			}
			if err := applyRestoredMetadata(metadata); err != nil {
				return err
			}
		case tar.TypeSymlink:
			// 링크 자체가 대상 디렉터리 안에 있어도 링크 값이 밖을 가리킬 수 있으므로 거부한다.
			return fmt.Errorf("보안을 위해 심볼릭 링크 복구를 거부합니다: %q", h.Name)
		default:
			return fmt.Errorf("지원하지 않는 TAR 항목 형식 %d: %q", h.Typeflag, h.Name)
		}
	}
	for i := len(directories) - 1; i >= 0; i-- {
		if err := applyRestoredMetadata(directories[i]); err != nil {
			return err
		}
	}
	return nil
}
