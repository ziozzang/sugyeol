package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type signingIdentity struct {
	Name        string    `json:"name"`
	Email       string    `json:"email"`
	CreatedAt   time.Time `json:"created_at"`
	PublicKey   string    `json:"public_key"`
	Fingerprint string    `json:"fingerprint"`
}

func sugyeolHome() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("홈 디렉터리 확인: %w", err)
	}
	return filepath.Join(home, ".sugyeol"), nil
}

func loadOrCreateKey() (ed25519.PrivateKey, []byte, error) {
	return loadKey(true)
}

func loadExistingKey() (ed25519.PrivateKey, []byte, error) {
	return loadKey(false)
}

func loadKey(create bool) (ed25519.PrivateKey, []byte, error) {
	dir, err := sugyeolHome()
	if err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, nil, err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, nil, err
	}
	path := filepath.Join(dir, "ed25519_private.pem")
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		if !create {
			return nil, nil, fmt.Errorf("private key is missing: %s", path)
		}
		pub, priv, genErr := ed25519.GenerateKey(nil)
		if genErr != nil {
			return nil, nil, genErr
		}
		der, marshalErr := x509.MarshalPKCS8PrivateKey(priv)
		if marshalErr != nil {
			return nil, nil, marshalErr
		}
		b := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		f, openErr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if openErr != nil {
			return nil, nil, openErr
		}
		if _, openErr = f.Write(b); openErr == nil {
			openErr = f.Sync()
		}
		closeErr := f.Close()
		if openErr != nil {
			return nil, nil, openErr
		}
		if closeErr != nil {
			return nil, nil, closeErr
		}
		return priv, publicPEM(pub), nil
	}
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("개인키가 일반 파일이 아닙니다: %s", path)
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, nil, fmt.Errorf("개인키 권한이 안전하지 않습니다(0600 필요): %s", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, nil, fmt.Errorf("개인키 PEM 해석 실패")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("개인키 해석: %w", err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("Ed25519 개인키가 아닙니다")
	}
	return priv, publicPEM(priv.Public().(ed25519.PublicKey)), nil
}

func initializeIdentity(name, email string) (signingIdentity, error) {
	name, email = strings.TrimSpace(name), strings.TrimSpace(email)
	if name == "" || email == "" || !strings.Contains(email, "@") {
		return signingIdentity{}, fmt.Errorf("name and a valid email are required")
	}
	dir, err := sugyeolHome()
	if err != nil {
		return signingIdentity{}, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return signingIdentity{}, err
	}
	identityPath := filepath.Join(dir, "identity.json")
	if _, err := os.Stat(identityPath); err == nil {
		return signingIdentity{}, fmt.Errorf("signing identity already exists: %s", identityPath)
	}
	priv, _, err := loadOrCreateKey()
	if err != nil {
		return signingIdentity{}, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	id := signingIdentity{Name: name, Email: email, CreatedAt: time.Now().UTC(), PublicKey: fmt.Sprintf("%x", pub), Fingerprint: publicFingerprint(pub)}
	b, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return signingIdentity{}, err
	}
	f, err := os.OpenFile(identityPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return signingIdentity{}, err
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return signingIdentity{}, err
	}
	if closeErr != nil {
		return signingIdentity{}, closeErr
	}
	return id, nil
}

func loadSigningIdentity() (ed25519.PrivateKey, []byte, signingIdentity, error) {
	dir, err := sugyeolHome()
	if err != nil {
		return nil, nil, signingIdentity{}, err
	}
	identityPath := filepath.Join(dir, "identity.json")
	info, err := os.Lstat(identityPath)
	if err == nil && (!info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0) {
		return nil, nil, signingIdentity{}, fmt.Errorf("identity file must be a regular 0600 file: %s", identityPath)
	}
	b, err := os.ReadFile(identityPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, signingIdentity{}, fmt.Errorf("signing identity is not initialized; run: sugyeol key init --name <name> --email <email>")
		}
		return nil, nil, signingIdentity{}, err
	}
	var id signingIdentity
	if err := json.Unmarshal(b, &id); err != nil {
		return nil, nil, id, err
	}
	if id.Name == "" || id.Email == "" {
		return nil, nil, id, fmt.Errorf("signing identity is incomplete")
	}
	priv, pubPEM, err := loadExistingKey()
	if err != nil {
		return nil, nil, id, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	if id.PublicKey != fmt.Sprintf("%x", pub) || id.Fingerprint != publicFingerprint(pub) {
		return nil, nil, id, fmt.Errorf("identity does not match the private key")
	}
	return priv, pubPEM, id, nil
}

func publicPEM(pub ed25519.PublicKey) []byte {
	der, _ := x509.MarshalPKIXPublicKey(pub)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func parsePublicPEM(b []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("공개키 PEM 해석 실패")
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("Ed25519 공개키가 아닙니다")
	}
	return pub, nil
}
