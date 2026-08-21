package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

func unpack(paths []string, out string) error {
	parts, err := verifyParts(paths, false)
	if err != nil {
		return err
	}
	tarFile, err := os.CreateTemp("", "packer-restore-*.tar")
	if err != nil {
		return err
	}
	defer func() { tarFile.Close(); os.Remove(tarFile.Name()) }()
	for _, p := range parts {
		zr, payload, err := payloadReader(p.path)
		if err != nil {
			return err
		}
		nonce, _ := decodeNonce(p.m.Nonce)
		h := sha256.New()
		var decoded io.Reader = payload
		if p.m.Scramble == "xor-sha256-counter-v1" {
			decoded = newXORReader(payload, p.m.SetID, p.m.Part, nonce)
		}
		n, copyErr := io.Copy(io.MultiWriter(tarFile, h), decoded)
		closeErr := payload.Close()
		zipCloseErr := zr.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if zipCloseErr != nil {
			return zipCloseErr
		}
		if n != p.m.PayloadSize || hex.EncodeToString(h.Sum(nil)) != p.m.PayloadSHA256 {
			return fmt.Errorf("파트 %d의 원본 payload SHA-256 불일치", p.m.Part)
		}
	}
	if _, err := tarFile.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := extractTar(tarFile, out); err != nil {
		return err
	}
	fmt.Printf(tr("restored"), parts[0].m.SourceName, out)
	return nil
}
