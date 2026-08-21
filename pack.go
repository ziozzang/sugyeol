package main

import (
	"archive/zip"
	"compress/flate"
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
	return packWithOptions(source, outPrefix, maxSize, scramble, nil, compressionConfig{method: zip.Store})
}

func packWithPassword(source, outPrefix string, maxSize int64, scramble bool, password []byte) error {
	return packWithOptions(source, outPrefix, maxSize, scramble, password, compressionConfig{method: zip.Store})
}

func packWithOptions(source, outPrefix string, maxSize int64, scramble bool, password []byte, compression compressionConfig) error {
	return packWithOptionsAndParts(source, outPrefix, maxSize, scramble, password, compression, 0)
}

func packWithOptionsAndParts(source, outPrefix string, maxSize int64, scramble bool, password []byte, compression compressionConfig, requestedParts int) error {
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
	var master []byte
	kdfSalt := ""
	if len(password) > 0 {
		uiVerbosef("deriving package encryption key with Argon2id")
		kdfSalt, err = randomHex(16)
		if err != nil {
			return err
		}
		master, err = deriveMasterKey(password, kdfSalt, kdfMemory, kdfTime, kdfParallelism)
		if err != nil {
			return err
		}
		defer clearBytes(master)
	}
	payloadCap := packagePayloadCapacity(maxSize, len(master) > 0, compression)
	if requestedParts > 0 {
		if int64(requestedParts) > tarSize {
			return fmt.Errorf("cannot split %d-byte TAR payload into %d non-empty parts", tarSize, requestedParts)
		}
		payloadCap = (tarSize + int64(requestedParts) - 1) / int64(requestedParts)
		largestStored := payloadCap
		if len(master) > 0 {
			largestStored = encryptedStoredSize(payloadCap)
		}
		maxSize = metadataReserve + compressedPayloadUpperBound(largestStored, compression)
	}
	if payloadCap <= 0 {
		return fmt.Errorf("part size is too small for metadata")
	}
	total := int((tarSize + payloadCap - 1) / payloadCap)
	if requestedParts > 0 {
		total = requestedParts
	}
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
	var offset int64
	progress := newProgress(tr("progress_pack"), tarSize)
	for part := 1; part <= total; part++ {
		if err := checkCanceled(); err != nil {
			progress.Finish(err)
			return err
		}
		remaining := tarSize - offset
		amount := payloadCap
		if requestedParts > 0 {
			partsRemaining := int64(total - part + 1)
			amount = (remaining + partsRemaining - 1) / partsRemaining
		} else if remaining < amount {
			amount = remaining
		}
		name := fmt.Sprintf("%s.part-%06d-of-%06d.zip", outPrefix, part, total)
		scrambleMethod := "none"
		if scramble && len(master) == 0 {
			scrambleMethod = "xor-sha256-counter-v1"
		}
		encryption := "none"
		if len(master) > 0 {
			encryption = encryptionName
		}
		partManifest := manifest{
			Format: formatName, Version: formatVersion, SetID: setID, SourceName: sourceName,
			Part: part, TotalParts: total, MaxPartSize: maxSize, PayloadOffset: offset,
			PayloadSize: amount, StoredSize: amount, Scramble: scrambleMethod, Encryption: encryption,
			KDF: func() string {
				if len(master) > 0 {
					return kdfName
				}
				return ""
			}(), KDFSalt: kdfSalt,
			KDFMemory: func() uint32 {
				if len(master) > 0 {
					return kdfMemory
				}
				return 0
			}(), KDFTime: func() uint32 {
				if len(master) > 0 {
					return kdfTime
				}
				return 0
			}(),
			KDFParallelism: func() uint8 {
				if len(master) > 0 {
					return kdfParallelism
				}
				return 0
			}(),
		}
		compression.apply(&partManifest)
		uiVerbosef("part %d/%d: offset=%d payload=%s output=%s", part, total, offset, humanSize(amount), name)
		if err := writePart(name, tarFile, amount, partManifest, priv, pubPEM, identity, master, compression, progress); err != nil {
			progress.Finish(err)
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
		offset += amount
	}
	progress.Finish(nil)
	ok = true
	return nil
}

func writePart(path string, tarFile *os.File, amount int64, m manifest, priv ed25519.PrivateKey, pubPEM []byte, identity signingIdentity, master []byte, compression compressionConfig, progress *progressBar) error {
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
	scrambled, err := os.CreateTemp("", "sugyeol-payload-*.bin")
	if err != nil {
		return err
	}
	defer func() { scrambled.Close(); os.Remove(scrambled.Name()) }()
	originalHash, scrambledHash := sha256.New(), sha256.New()
	var n int64
	if m.Encryption == encryptionName {
		m.EncryptionNonce, err = randomHex(12)
		if err != nil {
			return err
		}
		n, err = encryptPayload(scrambled, io.LimitReader(tarFile, amount), m, master, m.EncryptionNonce, io.MultiWriter(originalHash, progress), scrambledHash)
		m.StoredSize = n
	} else {
		raw := io.TeeReader(io.LimitReader(tarFile, amount), io.MultiWriter(originalHash, progress))
		var payloadReader io.Reader = raw
		if m.Scramble == "xor-sha256-counter-v1" {
			payloadReader = newXORReader(raw, m.SetID, m.Part, nonceBytes)
		}
		n, err = io.Copy(io.MultiWriter(scrambled, scrambledHash), payloadReader)
	}
	if err != nil {
		return err
	}
	expectedStored := amount
	if m.Encryption == encryptionName {
		expectedStored = encryptedStoredSize(amount)
	}
	if n != expectedStored {
		return fmt.Errorf("stored payload size mismatch: %d != %d", n, expectedStored)
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
	if compression.method == zip.Deflate {
		zw.RegisterCompressor(zip.Deflate, func(w io.Writer) (io.WriteCloser, error) {
			return flate.NewWriter(w, compression.level)
		})
	}
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
	h := &zip.FileHeader{Name: "payload.scrambled", Method: compression.method}
	h.SetMode(0644)
	w, err := zw.CreateHeader(h)
	if err != nil {
		return err
	}
	progressKey := "progress_write_part"
	if compression.method == zip.Deflate {
		progressKey = "progress_compress_part"
	}
	writeProgress := newProgress(tr(progressKey, m.Part, m.TotalParts), m.StoredSize)
	_, copyErr := io.Copy(w, writeProgress.Reader(scrambled))
	writeProgress.Finish(copyErr)
	if copyErr != nil {
		return copyErr
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
