package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

func unpack(paths []string, out string) error {
	return unpackWithPassword(paths, out, nil)
}

func unpackWithPassword(paths []string, out string, password []byte) error {
	parts, err := verifyParts(paths, false)
	if err != nil {
		return err
	}
	tarFile, err := os.CreateTemp("", "sugyeol-restore-*.tar")
	if err != nil {
		return err
	}
	defer func() { tarFile.Close(); os.Remove(tarFile.Name()) }()
	var master []byte
	if parts[0].m.Encryption == encryptionName {
		if len(password) == 0 {
			password, err = readEncryptionPassword("", false)
			if err != nil {
				return err
			}
			defer clearBytes(password)
		}
		master, err = deriveMasterKey(password, parts[0].m.KDFSalt, parts[0].m.KDFMemory, parts[0].m.KDFTime, parts[0].m.KDFParallelism)
		if err != nil {
			return err
		}
		defer clearBytes(master)
	}
	for _, p := range parts {
		zr, payload, err := payloadReader(p.path)
		if err != nil {
			return err
		}
		nonce, _ := decodeNonce(p.m.Nonce)
		h := sha256.New()
		var n int64
		var copyErr error
		if p.m.Encryption == encryptionName {
			n, copyErr = decryptPayload(tarFile, payload, p.m, master, h)
		} else {
			var decoded io.Reader = payload
			if p.m.Scramble == "xor-sha256-counter-v1" {
				decoded = newXORReader(payload, p.m.SetID, p.m.Part, nonce)
			}
			n, copyErr = io.Copy(io.MultiWriter(tarFile, h), decoded)
		}
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
