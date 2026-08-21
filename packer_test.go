package main

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestParseSizeDefaultIsMB(t *testing.T) {
	got, err := parseSize("10")
	if err != nil || got != 10_000_000 {
		t.Fatalf("parseSize(10) = %d, %v", got, err)
	}
	got, err = parseSize("10MiB")
	if err != nil || got != 10<<20 {
		t.Fatalf("parseSize(10MiB) = %d, %v", got, err)
	}
}

func initTestIdentity(t *testing.T, name, email string) {
	t.Helper()
	if _, err := initializeIdentity(name, email); err != nil {
		t.Fatal(err)
	}
}

func TestPackVerifyUnpackRoundTrip(t *testing.T) {
	t.Setenv("HOME", filepath.Join(t.TempDir(), "home"))
	initTestIdentity(t, "Test Signer", "test@example.com")
	inputParent := t.TempDir()
	input := filepath.Join(inputParent, "source")
	if err := os.MkdirAll(filepath.Join(input, "nested"), 0755); err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte("signed split archive\x00"), 2500)
	if err := os.WriteFile(filepath.Join(input, "nested", "data.bin"), data, 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(input, "empty"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	outDir := t.TempDir()
	prefix := filepath.Join(outDir, "bundle")
	const max = int64(20 * 1024)
	if err := pack(input, prefix, max, true); err != nil {
		t.Fatal(err)
	}
	parts, err := filepath.Glob(prefix + ".part-*.zip")
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(parts)
	if len(parts) < 2 {
		t.Fatalf("expected multiple parts, got %d", len(parts))
	}
	for _, part := range parts {
		st, err := os.Stat(part)
		if err != nil {
			t.Fatal(err)
		}
		if st.Size() > max {
			t.Fatalf("%s exceeds max: %d", part, st.Size())
		}
	}
	verifiedParts, err := verifyParts(parts, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range verifiedParts {
		if p.m.SignerName != "Test Signer" || p.m.SignerEmail != "test@example.com" || len(p.m.SignatureSalt) != 32 {
			t.Fatal("ZIP signed identity metadata missing")
		}
	}
	restore := t.TempDir()
	if err := unpack(parts, restore); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(restore, "source", "nested", "data.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("restored data differs")
	}
	keyInfo, err := os.Stat(filepath.Join(os.Getenv("HOME"), ".packer", "ed25519_private.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if keyInfo.Mode().Perm() != 0600 {
		t.Fatalf("private key mode = %o", keyInfo.Mode().Perm())
	}
	identityInfo, err := os.Stat(filepath.Join(os.Getenv("HOME"), ".packer", "identity.json"))
	if err != nil || identityInfo.Mode().Perm() != 0600 {
		t.Fatalf("identity mode: %v, %v", identityInfo, err)
	}
}

func TestSigningRequiresInitializedIdentity(t *testing.T) {
	t.Setenv("HOME", filepath.Join(t.TempDir(), "home"))
	input := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(input, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := pack(input, filepath.Join(t.TempDir(), "bundle"), 32*1024, true); err == nil {
		t.Fatal("pack signed without initialized identity")
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("HOME"), ".packer", "ed25519_private.pem")); !os.IsNotExist(err) {
		t.Fatalf("private key was created before identity init: %v", err)
	}
}

func TestVerifyRejectsMutation(t *testing.T) {
	t.Setenv("HOME", filepath.Join(t.TempDir(), "home"))
	initTestIdentity(t, "Test Signer", "test@example.com")
	input := filepath.Join(t.TempDir(), "input.bin")
	if err := os.WriteFile(input, bytes.Repeat([]byte{0x5a}, 5000), 0600); err != nil {
		t.Fatal(err)
	}
	prefix := filepath.Join(t.TempDir(), "bundle")
	if err := pack(input, prefix, 32*1024, true); err != nil {
		t.Fatal(err)
	}
	parts, _ := filepath.Glob(prefix + ".part-*.zip")
	b, err := os.ReadFile(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)/2] ^= 0xff
	if err := os.WriteFile(parts[0], b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyParts(parts, false); err == nil {
		t.Fatal("mutation was not detected")
	}
}

func TestPackWithoutScrambling(t *testing.T) {
	t.Setenv("HOME", filepath.Join(t.TempDir(), "home"))
	initTestIdentity(t, "Test Signer", "test@example.com")
	input := filepath.Join(t.TempDir(), "plain.bin")
	data := bytes.Repeat([]byte("plain payload"), 1000)
	if err := os.WriteFile(input, data, 0600); err != nil {
		t.Fatal(err)
	}
	prefix := filepath.Join(t.TempDir(), "bundle")
	if err := pack(input, prefix, 32*1024, false); err != nil {
		t.Fatal(err)
	}
	parts, _ := filepath.Glob(prefix + ".part-*.zip")
	verified, err := verifyParts(parts, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range verified {
		if p.m.Scramble != "none" {
			t.Fatalf("scramble = %q", p.m.Scramble)
		}
	}
	restore := t.TempDir()
	if err := unpack(parts, restore); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(restore, "plain.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("plain round trip differs")
	}
}

func TestDetachedDirectorySignature(t *testing.T) {
	t.Setenv("HOME", filepath.Join(t.TempDir(), "home"))
	initTestIdentity(t, "Test Signer", "test@example.com")
	source := filepath.Join(t.TempDir(), "tree")
	if err := os.MkdirAll(filepath.Join(source, "nested"), 0755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(source, "nested", "file.txt")
	if err := os.WriteFile(file, []byte("original"), 0644); err != nil {
		t.Fatal(err)
	}
	sigPath := filepath.Join(t.TempDir(), "tree.meta")
	if err := signCommand([]string{"-out", sigPath, "-label", "test", source}); err != nil {
		t.Fatal(err)
	}
	if err := verifyDetached(sigPath, source, nil, 1); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("changed"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := verifyDetached(sigPath, source, nil, 1); err == nil {
		t.Fatal("changed directory verified")
	}
}

func TestSignatureChainRequiresValidPriorChainAndSource(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "artifact.bin")
	if err := os.WriteFile(source, []byte("chain content"), 0644); err != nil {
		t.Fatal(err)
	}
	meta := filepath.Join(root, "artifact.meta")
	home1 := filepath.Join(t.TempDir(), "signer1")
	t.Setenv("HOME", home1)
	initTestIdentity(t, "Alice", "alice@example.com")
	_, pub1, _, err := loadSigningIdentity()
	if err != nil {
		t.Fatal(err)
	}
	pub1Path := filepath.Join(root, "alice.pem")
	if err := os.WriteFile(pub1Path, pub1, 0644); err != nil {
		t.Fatal(err)
	}
	if err := signCommand([]string{"-out", meta, "-label", "author", source}); err != nil {
		t.Fatal(err)
	}
	home2 := filepath.Join(t.TempDir(), "signer2")
	if err := os.Setenv("HOME", home2); err != nil {
		t.Fatal(err)
	}
	initTestIdentity(t, "Bob", "bob@example.com")
	_, pub2, _, err := loadSigningIdentity()
	if err != nil {
		t.Fatal(err)
	}
	pub2Path := filepath.Join(root, "bob.pem")
	if err := os.WriteFile(pub2Path, pub2, 0644); err != nil {
		t.Fatal(err)
	}
	if err := endorseCommand([]string{"-source", source, "-label", "reviewer", "-pubkey", pub1Path, meta}); err != nil {
		t.Fatal(err)
	}
	if err := verifyDetached(meta, source, []string{pub1Path, pub2Path}, 2); err != nil {
		t.Fatal(err)
	}
	validMeta, err := os.ReadFile(meta)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("modified before endorsement"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := endorseCommand([]string{"-source", source, "-pubkey", pub1Path, meta}); err == nil {
		t.Fatal("endorsement accepted changed source")
	}
	unchangedMeta, err := os.ReadFile(meta)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(validMeta, unchangedMeta) {
		t.Fatal("failed source verification modified metadata")
	}
	if err := os.WriteFile(source, []byte("chain content"), 0644); err != nil {
		t.Fatal(err)
	}
	bundle, _, err := loadSignatureBundle(meta)
	if err != nil {
		t.Fatal(err)
	}
	bundle.Records[0].SignerName = "Mallory"
	if err := writeSignatureBundle(meta, bundle); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(meta)
	if err != nil {
		t.Fatal(err)
	}
	if err := endorseCommand([]string{"-source", source, "-pubkey", pub1Path, meta}); err == nil {
		t.Fatal("endorsement accepted a broken prior chain")
	}
	after, err := os.ReadFile(meta)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("failed endorsement modified metadata")
	}
}

func TestI18NLanguageSelection(t *testing.T) {
	original := currentLanguage
	defer func() { currentLanguage = original }()
	setLanguage("ko_KR.UTF-8")
	if got := tr("command_required"); got != "명령이 필요합니다" {
		t.Fatalf("ko: %q", got)
	}
	setLanguage("en_US.UTF-8")
	if got := tr("command_required"); got != "a command is required" {
		t.Fatalf("en: %q", got)
	}
}

func TestCompareVersionsAndAssetNames(t *testing.T) {
	if compareVersions("1.2.0", "1.1.9") <= 0 {
		t.Fatal("version comparison")
	}
	name, err := releaseAssetName("1.0.0", "linux", "amd64")
	if err != nil || name != "packer_1.0.0_linux_x86_64" {
		t.Fatalf("asset = %q, %v", name, err)
	}
}
