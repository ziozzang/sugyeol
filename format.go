package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
)

const (
	formatName            = "sugyeol-split-zip"
	formatVersion         = 1
	metadataReserve int64 = 16 * 1024
)

type manifest struct {
	Format          string `json:"format"`
	Version         int    `json:"version"`
	SetID           string `json:"set_id"`
	SourceName      string `json:"source_name"`
	Part            int    `json:"part"`
	TotalParts      int    `json:"total_parts"`
	MaxPartSize     int64  `json:"max_part_size"`
	PayloadOffset   int64  `json:"payload_offset"`
	PayloadSize     int64  `json:"payload_size"`
	StoredSize      int64  `json:"stored_size"`
	PayloadSHA256   string `json:"payload_sha256"`
	ScrambledSHA256 string `json:"scrambled_sha256"`
	Nonce           string `json:"nonce"`
	Scramble        string `json:"scramble"`
	Encryption      string `json:"encryption"`
	KDF             string `json:"kdf,omitempty"`
	KDFSalt         string `json:"kdf_salt,omitempty"`
	KDFMemory       uint32 `json:"kdf_memory_kib,omitempty"`
	KDFTime         uint32 `json:"kdf_time,omitempty"`
	KDFParallelism  uint8  `json:"kdf_parallelism,omitempty"`
	EncryptionNonce string `json:"encryption_nonce,omitempty"`
	SignerName      string `json:"signer_name"`
	SignerEmail     string `json:"signer_email"`
	SignedAt        string `json:"signed_at"`
	SignatureSalt   string `json:"signature_salt"`
	Signature       string `json:"signature"`
	PublicKey       string `json:"public_key"`
}

func canonicalManifest(m manifest) ([]byte, error) {
	m.Signature = "signature.ed25519"
	m.PublicKey = "public_key.pem"
	return json.MarshalIndent(m, "", "  ")
}

type xorReader struct {
	r       io.Reader
	seed    [32]byte
	counter uint64
	block   [32]byte
	pos     int
}

func newXORReader(r io.Reader, setID string, part int, nonce []byte) *xorReader {
	h := sha256.New()
	h.Write([]byte("sugyeol-scramble-v1\x00"))
	h.Write([]byte(setID))
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(part))
	h.Write(b[:])
	h.Write(nonce)
	x := &xorReader{r: r, pos: 32}
	copy(x.seed[:], h.Sum(nil))
	return x
}

func (x *xorReader) Read(p []byte) (int, error) {
	n, err := x.r.Read(p)
	for i := 0; i < n; i++ {
		if x.pos == len(x.block) {
			var c [8]byte
			binary.BigEndian.PutUint64(c[:], x.counter)
			h := sha256.New()
			h.Write(x.seed[:])
			h.Write(c[:])
			copy(x.block[:], h.Sum(nil))
			x.counter++
			x.pos = 0
		}
		p[i] ^= x.block[x.pos]
		x.pos++
	}
	return n, err
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func decodeNonce(s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 16 {
		return nil, fmt.Errorf("잘못된 nonce")
	}
	return b, nil
}

func signManifest(m manifest, key ed25519.PrivateKey) ([]byte, []byte, error) {
	b, err := canonicalManifest(m)
	if err != nil {
		return nil, nil, err
	}
	return b, ed25519.Sign(key, b), nil
}
