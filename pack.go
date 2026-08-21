package main

import (
	"archive/zip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

func pack(source, outPrefix string, maxSize int64, scramble bool) error {
	if maxSize <= metadataReserve {
		return fmt.Errorf("파트 크기는 최소 %d 바이트보다 커야 합니다", metadataReserve)
	}
	tarFile, tarSize, sourceName, err := makeTar(source)
	if err != nil {
		return err
	}
	defer func() { tarFile.Close(); os.Remove(tarFile.Name()) }()
	priv, pubPEM, identity, err := loadSigningIdentity()
	if err != nil {
		return err
	}
	setID, err := randomHex(16)
	if err != nil {
		return err
	}
	payloadCap := maxSize - metadataReserve
	total := int((tarSize + payloadCap - 1) / payloadCap)
	if total < 1 {
		total = 1
	}
	created := make([]string, 0, total)
	ok := false
	defer func() {
		if !ok {
			for _, p := range created {
				_ = os.Remove(p)
			}
		}
	}()
	for part := 1; part <= total; part++ {
		offset := int64(part-1) * payloadCap
		remaining := tarSize - offset
		amount := payloadCap
		if remaining < amount {
			amount = remaining
		}
		name := fmt.Sprintf("%s.part-%06d-of-%06d.zip", outPrefix, part, total)
		scrambleMethod := "none"
		if scramble {
			scrambleMethod = "xor-sha256-counter-v1"
		}
		if err := writePart(name, tarFile, amount, manifest{
			Format: formatName, Version: formatVersion, SetID: setID, SourceName: sourceName,
			Part: part, TotalParts: total, MaxPartSize: maxSize, PayloadOffset: offset,
			PayloadSize: amount, Scramble: scrambleMethod,
		}, priv, pubPEM, identity); err != nil {
			return err
		}
		created = append(created, name)
		st, err := os.Stat(name)
		if err != nil {
			return err
		}
		if st.Size() > maxSize {
			return fmt.Errorf("내부 오류: %s가 최대 크기를 초과했습니다 (%d > %d)", name, st.Size(), maxSize)
		}
		fmt.Printf(tr("created"), name, st.Size())
	}
	ok = true
	return nil
}

func writePart(path string, tarFile *os.File, amount int64, m manifest, priv ed25519.PrivateKey, pubPEM []byte, identity signingIdentity) error {
	nonce, err := randomHex(16)
	if err != nil {
		return err
	}
	m.Nonce = nonce
	m.SignerName, m.SignerEmail = identity.Name, identity.Email
	m.SignedAt = time.Now().UTC().Format(time.RFC3339Nano)
	m.SignatureSalt, err = randomHex(16)
	if err != nil {
		return err
	}
	nonceBytes, _ := decodeNonce(nonce)
	scrambled, err := os.CreateTemp("", "packer-payload-*.bin")
	if err != nil {
		return err
	}
	defer func() { scrambled.Close(); os.Remove(scrambled.Name()) }()
	originalHash, scrambledHash := sha256.New(), sha256.New()
	raw := io.TeeReader(io.LimitReader(tarFile, amount), originalHash)
	var payloadReader io.Reader = raw
	if m.Scramble == "xor-sha256-counter-v1" {
		payloadReader = newXORReader(raw, m.SetID, m.Part, nonceBytes)
	}
	n, err := io.Copy(io.MultiWriter(scrambled, scrambledHash), payloadReader)
	if err != nil {
		return err
	}
	if n != amount {
		return fmt.Errorf("원본 TAR가 예상보다 짧습니다: %d != %d", n, amount)
	}
	m.PayloadSHA256 = hex.EncodeToString(originalHash.Sum(nil))
	m.ScrambledSHA256 = hex.EncodeToString(scrambledHash.Sum(nil))
	manifestBytes, sig, err := signManifest(m, priv)
	if err != nil {
		return err
	}
	if _, err := scrambled.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("출력 생성 %s: %w", path, err)
	}
	keep := false
	defer func() {
		f.Close()
		if !keep {
			os.Remove(path)
		}
	}()
	zw := zip.NewWriter(f)
	entries := []struct {
		name string
		data []byte
	}{
		{"manifest.json", manifestBytes}, {"signature.ed25519", sig}, {"public_key.pem", pubPEM},
	}
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Method: zip.Store}
		h.SetMode(0644)
		w, err := zw.CreateHeader(h)
		if err != nil {
			return err
		}
		if _, err := w.Write(e.data); err != nil {
			return err
		}
	}
	h := &zip.FileHeader{Name: "payload.scrambled", Method: zip.Store}
	h.SetMode(0644)
	w, err := zw.CreateHeader(h)
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, scrambled); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	keep = true
	return nil
}
