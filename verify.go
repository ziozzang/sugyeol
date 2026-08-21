package main

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

type verifiedPart struct {
	path      string
	m         manifest
	publicKey []byte
}

func verifyPinnedPartKey(parts []verifiedPart, trusted string) error {
	if len(parts) == 0 {
		return fmt.Errorf("no parts")
	}
	want, err := loadPinnedPublicKey(trusted)
	if err != nil {
		return err
	}
	got, err := parsePublicPEM(parts[0].publicKey)
	if err != nil {
		return err
	}
	if !got.Equal(want) {
		return fmt.Errorf("archive key does not match the trusted public key")
	}
	return nil
}

func verifyParts(paths []string, verbose bool) ([]verifiedPart, error) {
	parts := make([]verifiedPart, 0, len(paths))
	for _, path := range paths {
		if err := checkCanceled(); err != nil {
			return nil, err
		}
		uiVerbosef("verifying package part: %s", path)
		p, err := verifyPart(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		parts = append(parts, p)
		if verbose {
			fmt.Printf(tr("verified"), path, p.m.Part, p.m.TotalParts)
		}
	}
	sort.Slice(parts, func(i, j int) bool { return parts[i].m.Part < parts[j].m.Part })
	if len(parts) == 0 {
		return nil, fmt.Errorf("파트가 없습니다")
	}
	first := parts[0]
	if len(parts) != first.m.TotalParts {
		return nil, fmt.Errorf("파트 수 불일치: %d개 제공, %d개 필요", len(parts), first.m.TotalParts)
	}
	var expectedOffset int64
	for i, p := range parts {
		if p.m.Part != i+1 {
			return nil, fmt.Errorf("파트 %d가 없거나 중복되었습니다", i+1)
		}
		if p.m.SetID != first.m.SetID || p.m.TotalParts != first.m.TotalParts || p.m.SourceName != first.m.SourceName || p.m.MaxPartSize != first.m.MaxPartSize || p.m.Scramble != first.m.Scramble || p.m.Compression != first.m.Compression || p.m.CompressionLevel != first.m.CompressionLevel || p.m.Encryption != first.m.Encryption || p.m.KDF != first.m.KDF || p.m.KDFSalt != first.m.KDFSalt || p.m.KDFMemory != first.m.KDFMemory || p.m.KDFTime != first.m.KDFTime || p.m.KDFParallelism != first.m.KDFParallelism || p.m.SignerName != first.m.SignerName || p.m.SignerEmail != first.m.SignerEmail {
			return nil, fmt.Errorf("서로 다른 패키지의 파트가 섞여 있습니다")
		}
		if !bytes.Equal(p.publicKey, first.publicKey) {
			return nil, fmt.Errorf("파트 공개키가 서로 다릅니다")
		}
		if p.m.PayloadOffset != expectedOffset {
			return nil, fmt.Errorf("파트 %d의 payload offset이 연속적이지 않습니다", p.m.Part)
		}
		if p.m.PayloadSize > 0 && expectedOffset > (1<<63-1)-p.m.PayloadSize {
			return nil, fmt.Errorf("package payload size overflow")
		}
		expectedOffset += p.m.PayloadSize
	}
	return parts, nil
}

func printPackageVerification(w io.Writer, parts []verifiedPart, pinned bool) error {
	if len(parts) == 0 {
		return fmt.Errorf("no verified package parts")
	}
	first := parts[0]
	pub, err := parsePublicPEM(first.publicKey)
	if err != nil {
		return err
	}
	firstSigned, err := time.Parse(time.RFC3339Nano, first.m.SignedAt)
	if err != nil {
		return err
	}
	lastSigned := firstSigned
	var payloadBytes int64
	for _, p := range parts {
		at, err := time.Parse(time.RFC3339Nano, p.m.SignedAt)
		if err != nil {
			return err
		}
		if at.Before(firstSigned) {
			firstSigned = at
		}
		if at.After(lastSigned) {
			lastSigned = at
		}
		if p.m.PayloadSize > 0 && payloadBytes > (1<<63-1)-p.m.PayloadSize {
			return fmt.Errorf("package payload size overflow")
		}
		payloadBytes += p.m.PayloadSize
	}
	trust := tr("signature_trust_unpinned")
	if pinned {
		trust = tr("signature_trust_pinned")
	}
	fmt.Fprintf(w, tr("package_signature_ok"), first.m.SourceName)
	fmt.Fprintf(w, tr("package_subject"), first.m.SetID, len(parts), humanSize(payloadBytes))
	compression := first.m.Compression
	if compression == "" {
		compression = "none"
	} else {
		compression = fmt.Sprintf("%s(level=%d)", compression, first.m.CompressionLevel)
	}
	fmt.Fprintf(w, tr("package_protection"), first.m.Scramble, first.m.Encryption, compression)
	fmt.Fprintf(w, tr("signature_crypto_status"), tr("package_signatures_valid", len(parts), len(parts)))
	fmt.Fprintf(w, tr("signature_trust"), trust)
	fmt.Fprintf(w, tr("signature_signer"), first.m.SignerName+" <"+first.m.SignerEmail+">")
	fmt.Fprintf(w, tr("signed_at_range"), firstSigned.UTC().Format(time.RFC3339Nano), lastSigned.UTC().Format(time.RFC3339Nano))
	fmt.Fprintf(w, tr("signature_algorithm"), "ed25519 + sha256")
	fmt.Fprintf(w, tr("signature_public_key"), hex.EncodeToString(pub))
	fmt.Fprintf(w, tr("signature_fingerprint"), publicFingerprint(pub))
	if ui.verbose {
		for _, p := range parts {
			fmt.Fprintf(w, tr("package_part_detail"), p.m.Part, p.m.TotalParts, p.m.SignedAt, p.m.SignatureSalt, p.m.PayloadSHA256, p.m.ScrambledSHA256)
		}
	}
	return nil
}

func verifyPart(path string) (verifiedPart, error) {
	st, err := os.Stat(path)
	if err != nil {
		return verifiedPart{}, err
	}
	zr, err := zip.OpenReader(path)
	if err != nil {
		return verifiedPart{}, fmt.Errorf("ZIP 열기: %w", err)
	}
	defer zr.Close()
	entries := make(map[string]*zip.File)
	for _, f := range zr.File {
		if _, exists := entries[f.Name]; exists {
			return verifiedPart{}, fmt.Errorf("중복 ZIP 항목 %q", f.Name)
		}
		entries[f.Name] = f
	}
	if len(entries) != 4 {
		return verifiedPart{}, fmt.Errorf("ZIP 항목 수가 올바르지 않습니다: %d", len(entries))
	}
	manifestBytes, err := readSmall(entries["manifest.json"], 64*1024)
	if err != nil {
		return verifiedPart{}, fmt.Errorf("manifest: %w", err)
	}
	var m manifest
	if err := json.Unmarshal(manifestBytes, &m); err != nil {
		return verifiedPart{}, fmt.Errorf("manifest JSON: %w", err)
	}
	if m.Format != formatName || m.Version != formatVersion {
		return verifiedPart{}, fmt.Errorf("지원하지 않는 포맷/버전")
	}
	if m.Part < 1 || m.TotalParts < 1 || m.Part > m.TotalParts || m.PayloadSize < 0 || m.StoredSize < 0 || m.PayloadOffset < 0 {
		return verifiedPart{}, fmt.Errorf("잘못된 manifest 값")
	}
	if m.Signature != "signature.ed25519" || m.PublicKey != "public_key.pem" || (m.Scramble != "xor-sha256-counter-v1" && m.Scramble != "none") {
		return verifiedPart{}, fmt.Errorf("지원하지 않는 manifest 구성")
	}
	if m.Encryption != "none" && m.Encryption != encryptionName {
		return verifiedPart{}, fmt.Errorf("unsupported encryption")
	}
	compression, err := manifestCompression(m)
	if err != nil {
		return verifiedPart{}, err
	}
	if m.Encryption == encryptionName {
		if m.Scramble != "none" || m.KDF != kdfName || m.KDFMemory != kdfMemory || m.KDFTime != kdfTime || m.KDFParallelism != kdfParallelism {
			return verifiedPart{}, fmt.Errorf("invalid encryption parameters")
		}
		if _, err := hex.DecodeString(m.KDFSalt); err != nil || len(m.KDFSalt) != 32 {
			return verifiedPart{}, fmt.Errorf("invalid KDF salt")
		}
		if _, err := hex.DecodeString(m.EncryptionNonce); err != nil || len(m.EncryptionNonce) != 24 {
			return verifiedPart{}, fmt.Errorf("invalid encryption nonce")
		}
		if m.StoredSize != encryptedStoredSize(m.PayloadSize) {
			return verifiedPart{}, fmt.Errorf("invalid encrypted payload size")
		}
	} else if m.StoredSize != m.PayloadSize {
		return verifiedPart{}, fmt.Errorf("invalid stored payload size")
	}
	if strings.TrimSpace(m.SignerName) == "" || strings.TrimSpace(m.SignerEmail) == "" || !strings.Contains(m.SignerEmail, "@") || m.SignedAt == "" {
		return verifiedPart{}, fmt.Errorf("missing signed identity metadata")
	}
	if _, err := time.Parse(time.RFC3339Nano, m.SignedAt); err != nil {
		return verifiedPart{}, fmt.Errorf("invalid signed_at")
	}
	if _, err := decodeNonce(m.SignatureSalt); err != nil {
		return verifiedPart{}, fmt.Errorf("invalid signature salt")
	}
	if st.Size() > m.MaxPartSize {
		return verifiedPart{}, fmt.Errorf("최대 파트 크기 초과: %d > %d", st.Size(), m.MaxPartSize)
	}
	canonical, err := canonicalManifest(m)
	if err != nil {
		return verifiedPart{}, err
	}
	if !bytes.Equal(manifestBytes, canonical) {
		return verifiedPart{}, fmt.Errorf("manifest가 canonical 형식이 아닙니다")
	}
	sig, err := readSmall(entries["signature.ed25519"], 1024)
	if err != nil {
		return verifiedPart{}, fmt.Errorf("signature: %w", err)
	}
	pubPEM, err := readSmall(entries["public_key.pem"], 16*1024)
	if err != nil {
		return verifiedPart{}, fmt.Errorf("public key: %w", err)
	}
	pub, err := parsePublicPEM(pubPEM)
	if err != nil {
		return verifiedPart{}, err
	}
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, canonical, sig) {
		return verifiedPart{}, fmt.Errorf("서명 검증 실패")
	}
	payload := entries["payload.scrambled"]
	if payload == nil {
		return verifiedPart{}, fmt.Errorf("payload.scrambled 항목 없음")
	}
	if payload.Method != compression.method || payload.UncompressedSize64 != uint64(m.StoredSize) {
		return verifiedPart{}, fmt.Errorf("payload 크기/압축 방식 불일치")
	}
	r, err := payload.Open()
	if err != nil {
		return verifiedPart{}, err
	}
	h := sha256.New()
	progress := newProgress(tr("progress_verify_part", m.Part, m.TotalParts), m.StoredSize)
	n, copyErr := io.Copy(h, progress.Reader(r))
	closeErr := r.Close()
	progressErr := copyErr
	if progressErr == nil {
		progressErr = closeErr
	}
	progress.Finish(progressErr)
	if copyErr != nil {
		return verifiedPart{}, copyErr
	}
	if closeErr != nil {
		return verifiedPart{}, closeErr
	}
	if n != m.StoredSize || hex.EncodeToString(h.Sum(nil)) != m.ScrambledSHA256 {
		return verifiedPart{}, fmt.Errorf("스크램블 payload SHA-256 불일치")
	}
	if _, err := decodeNonce(m.Nonce); err != nil {
		return verifiedPart{}, err
	}
	if _, err := hex.DecodeString(m.PayloadSHA256); err != nil || len(m.PayloadSHA256) != 64 {
		return verifiedPart{}, fmt.Errorf("잘못된 payload SHA-256")
	}
	return verifiedPart{path: path, m: m, publicKey: pubPEM}, nil
}

func readSmall(f *zip.File, max uint64) ([]byte, error) {
	if f == nil {
		return nil, fmt.Errorf("항목 없음")
	}
	if f.UncompressedSize64 > max {
		return nil, fmt.Errorf("항목이 너무 큽니다")
	}
	r, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(io.LimitReader(r, int64(max)+1))
}

func payloadReader(path string) (*zip.ReadCloser, io.ReadCloser, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, nil, err
	}
	for _, f := range zr.File {
		if f.Name == "payload.scrambled" {
			r, err := f.Open()
			if err != nil {
				zr.Close()
				return nil, nil, err
			}
			return zr, r, nil
		}
	}
	zr.Close()
	return nil, nil, fmt.Errorf("payload 없음")
}
