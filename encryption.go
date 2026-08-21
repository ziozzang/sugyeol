package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

const (
	encryptionName         = "aes-256-gcm-chunked-v1"
	kdfName                = "argon2id-v1"
	kdfMemory       uint32 = 19 * 1024
	kdfTime         uint32 = 2
	kdfParallelism  uint8  = 1
	encryptionChunk int64  = 4 * 1024 * 1024
)

func readEncryptionPassword(path string, confirm bool) ([]byte, error) {
	if path != "" {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return nil, fmt.Errorf("password file must be a regular file with mode 0600 or stricter")
		}
		if info.Size() > 64*1024 {
			return nil, fmt.Errorf("password file is too large")
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
			b = b[:len(b)-1]
		}
		if len(b) < 8 {
			return nil, fmt.Errorf("encryption password must be at least 8 bytes")
		}
		return b, nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, fmt.Errorf("password input requires a terminal; use -password-file with a 0600 file")
	}
	fmt.Fprint(os.Stderr, "Encryption password: ")
	first, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	if len(first) < 8 {
		clearBytes(first)
		return nil, fmt.Errorf("encryption password must be at least 8 bytes")
	}
	if confirm {
		fmt.Fprint(os.Stderr, "Confirm password: ")
		second, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			clearBytes(first)
			return nil, err
		}
		if !hmac.Equal(first, second) {
			clearBytes(first)
			clearBytes(second)
			return nil, fmt.Errorf("passwords do not match")
		}
		clearBytes(second)
	}
	return first, nil
}

func passwordBytes(value string) ([]byte, error) {
	b := []byte(value)
	if len(b) < 8 {
		clearBytes(b)
		return nil, fmt.Errorf("encryption password must be at least 8 bytes")
	}
	return b, nil
}

func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func deriveMasterKey(password []byte, saltHex string, memory, rounds uint32, parallel uint8) ([]byte, error) {
	salt, err := hex.DecodeString(saltHex)
	if err != nil || len(salt) != 16 {
		return nil, fmt.Errorf("invalid encryption KDF salt")
	}
	if memory != kdfMemory || rounds != kdfTime || parallel != kdfParallelism {
		return nil, fmt.Errorf("unsupported Argon2id parameters")
	}
	return argon2.IDKey(password, salt, rounds, memory, parallel, 32), nil
}

func partAEAD(master []byte, setID string, part int) (cipher.AEAD, error) {
	h := hmac.New(sha256.New, master)
	h.Write([]byte("sugyeol-part-aead-v1\x00"))
	h.Write([]byte(setID))
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(part))
	h.Write(b[:])
	block, err := aes.NewCipher(h.Sum(nil))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func encryptionAAD(m manifest) []byte {
	return []byte(fmt.Sprintf("sugyeol-aead-v1\x00%s\x00%d\x00%d\x00%d\x00%d", m.SetID, m.Part, m.TotalParts, m.PayloadOffset, m.PayloadSize))
}

func encryptedStoredSize(plain int64) int64 {
	if plain == 0 {
		return 0
	}
	return plain + ((plain+encryptionChunk-1)/encryptionChunk)*16
}

func encryptionPayloadCapacity(maxSize int64) int64 {
	cap := maxSize - metadataReserve
	overhead := ((cap + encryptionChunk - 1) / encryptionChunk) * 16
	return cap - overhead
}

func encryptPayload(dst io.Writer, src io.Reader, m manifest, master []byte, nonceHex string, plainHash, cipherHash io.Writer) (int64, error) {
	aead, err := partAEAD(master, m.SetID, m.Part)
	if err != nil {
		return 0, err
	}
	base, err := hex.DecodeString(nonceHex)
	if err != nil || len(base) != aead.NonceSize() {
		return 0, fmt.Errorf("invalid encryption nonce")
	}
	remaining, counter, written := m.PayloadSize, uint32(0), int64(0)
	buf := make([]byte, encryptionChunk)
	aad := encryptionAAD(m)
	sealedBuffer := make([]byte, 0, int(encryptionChunk)+aead.Overhead())
	for remaining > 0 {
		n := int64(len(buf))
		if remaining < n {
			n = remaining
		}
		if _, err := io.ReadFull(src, buf[:n]); err != nil {
			return written, err
		}
		plainHash.Write(buf[:n])
		nonce := append([]byte(nil), base...)
		binary.BigEndian.PutUint32(nonce[len(nonce)-4:], counter)
		sealed := aead.Seal(sealedBuffer[:0], nonce, buf[:n], aad)
		if _, err := io.MultiWriter(dst, cipherHash).Write(sealed); err != nil {
			return written, err
		}
		written += int64(len(sealed))
		remaining -= n
		counter++
	}
	clearBytes(buf)
	return written, nil
}

func decryptPayload(dst io.Writer, src io.Reader, m manifest, master []byte, plainHash io.Writer) (int64, error) {
	aead, err := partAEAD(master, m.SetID, m.Part)
	if err != nil {
		return 0, err
	}
	base, err := hex.DecodeString(m.EncryptionNonce)
	if err != nil || len(base) != aead.NonceSize() {
		return 0, fmt.Errorf("invalid encryption nonce")
	}
	remaining, counter, written := m.PayloadSize, uint32(0), int64(0)
	aad := encryptionAAD(m)
	sealedBuffer := make([]byte, int(encryptionChunk)+aead.Overhead())
	for remaining > 0 {
		plainN := encryptionChunk
		if remaining < plainN {
			plainN = remaining
		}
		sealed := sealedBuffer[:plainN+int64(aead.Overhead())]
		if _, err := io.ReadFull(src, sealed); err != nil {
			return written, err
		}
		nonce := append([]byte(nil), base...)
		binary.BigEndian.PutUint32(nonce[len(nonce)-4:], counter)
		plain, err := aead.Open(sealed[:0], nonce, sealed, aad)
		if err != nil {
			return written, fmt.Errorf("incorrect password or damaged encrypted payload")
		}
		if _, err := io.MultiWriter(dst, plainHash).Write(plain); err != nil {
			return written, err
		}
		written += int64(len(plain))
		remaining -= plainN
		counter++
	}
	return written, nil
}
