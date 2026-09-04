package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestProgressVerboseDebugAndCancellation(t *testing.T) {
	oldUI, oldOutput, oldContext := ui, uiOutput, commandContext
	defer func() {
		ui, uiOutput, commandContext = oldUI, oldOutput, oldContext
	}()
	ui = uiSettings{mode: progressAuto}
	var output bytes.Buffer
	uiOutput = &output
	commandContext = context.Background()

	args, err := parseGlobalUIArgs([]string{"--verbose", "--debug", "--progress=always", "pack"})
	if err != nil {
		t.Fatal(err)
	}
	if len(args) != 1 || args[0] != "pack" || !ui.verbose || !ui.debug || ui.mode != progressAlways {
		t.Fatalf("global UI parsing failed: args=%v ui=%+v", args, ui)
	}
	p := newProgress("test transfer", 100)
	if _, err := p.Write(bytes.Repeat([]byte{'x'}, 50)); err != nil {
		t.Fatal(err)
	}
	p.Finish(nil)
	if got := output.String(); !strings.Contains(got, "50%") || !strings.Contains(got, "elapsed") || !strings.Contains(got, "ETA") || !strings.Contains(got, "done") {
		t.Fatalf("progress output is incomplete: %q", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	commandContext = ctx
	cancel()
	p = newProgress("canceled transfer", 10)
	_, err = p.Reader(strings.NewReader("0123456789")).Read(make([]byte, 10))
	p.Finish(err)
	if !errors.Is(err, context.Canceled) || !strings.Contains(output.String(), "canceled") {
		t.Fatalf("cancellation was not propagated: %v, %q", err, output.String())
	}

	if _, err := parseGlobalUIArgs([]string{"--progress=invalid", "version"}); err == nil {
		t.Fatal("invalid progress mode was accepted")
	}
	if got := effectiveCommand([]string{"--lang", "ko", "--verbose", "--progress=always", "update", "-v", "v1.5.0"}); got != "update" {
		t.Fatalf("effective command = %q", got)
	}
}

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

func TestWorkingTempUsesCurrentDirectoryAndCleansUp(t *testing.T) {
	work := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(work); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(old) }()

	file, err := createWorkingTemp("sugyeol-test-*.bin")
	if err != nil {
		t.Fatal(err)
	}
	wantDir := filepath.Join(work, "tmp")
	if filepath.Dir(filepath.Dir(file.Name())) != wantDir {
		t.Fatalf("working temp = %s, want root %s", file.Name(), wantDir)
	}
	cleanupWorkingTemp(file)
	if _, err := os.Stat(wantDir); !os.IsNotExist(err) {
		t.Fatalf("working tmp directory was not removed: %v", err)
	}
}

func TestMakeTarOfCurrentDirectoryExcludesItsWorkingFile(t *testing.T) {
	work := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(work); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(old) }()
	if err := os.WriteFile("source.txt", []byte("source"), 0600); err != nil {
		t.Fatal(err)
	}

	tarFile, _, _, err := makeTar(".")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanupWorkingTemp(tarFile)
	reader := tar.NewReader(tarFile)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(header.Name, "sugyeol-work-") || strings.Contains(header.Name, "sugyeol-source-") {
			t.Fatalf("working directory was included in its TAR: %s", header.Name)
		}
	}
}

func TestTarPreservesFilesystemMetadata(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "metadata.bin")
	if err := os.WriteFile(source, []byte("metadata preservation"), 0641); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(source, 0641); err != nil {
		t.Fatal(err)
	}
	accessTime := time.Date(2020, 2, 3, 4, 5, 6, 123456789, time.UTC)
	modTime := time.Date(2021, 3, 4, 5, 6, 7, 987654321, time.UTC)
	if err := os.Chtimes(source, accessTime, modTime); err != nil {
		t.Fatal(err)
	}
	sourceInfo, err := os.Stat(source)
	if err != nil {
		t.Fatal(err)
	}
	_, sourceBirth, sourceHasBirth, err := platformFileTimes(source, sourceInfo)
	if err != nil {
		t.Fatal(err)
	}
	tarFile, _, _, err := makeTar(source)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanupWorkingTemp(tarFile)
	}()
	header, err := tar.NewReader(tarFile).Next()
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && os.FileMode(header.Mode)&os.ModePerm != 0641 {
		t.Fatalf("archived mode = %o", header.Mode)
	}
	if !timestampsClose(header.ModTime, modTime) || !timestampsClose(header.AccessTime, accessTime) {
		t.Fatalf("archived times: mtime=%s atime=%s", header.ModTime, header.AccessTime)
	}
	if sourceHasBirth && header.PAXRecords[sugyeolBirthTimePAX] == "" {
		t.Fatal("creation time was not retained in PAX metadata")
	}
	if _, err := tarFile.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	restore := t.TempDir()
	if err := extractTar(tarFile, restore); err != nil {
		t.Fatal(err)
	}
	restored := filepath.Join(restore, "metadata.bin")
	restoredInfo, err := os.Stat(restored)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && restoredInfo.Mode().Perm() != 0641 {
		t.Fatalf("restored mode = %o", restoredInfo.Mode().Perm())
	}
	restoredAccess, restoredBirth, restoredHasBirth, err := platformFileTimes(restored, restoredInfo)
	if err != nil {
		t.Fatal(err)
	}
	if !timestampsClose(restoredInfo.ModTime(), modTime) || !timestampsClose(restoredAccess, accessTime) {
		t.Fatalf("restored times: mtime=%s atime=%s", restoredInfo.ModTime(), restoredAccess)
	}
	if sourceHasBirth && restoredHasBirth && (runtime.GOOS == "darwin" || runtime.GOOS == "windows") && !timestampsClose(restoredBirth, sourceBirth) {
		t.Fatalf("restored creation time = %s, want %s", restoredBirth, sourceBirth)
	}
}

func timestampsClose(a, b time.Time) bool {
	delta := a.Sub(b)
	if delta < 0 {
		delta = -delta
	}
	return delta <= time.Second
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
	parts, err := filepath.Glob(prefix + "_part-*.zip")
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(parts)
	if len(parts) < 2 {
		t.Fatalf("expected multiple parts, got %d", len(parts))
	}
	if !strings.HasPrefix(filepath.Base(parts[0]), "bundle_part-") {
		t.Fatalf("unexpected part name: %s", parts[0])
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
	var packageSummary bytes.Buffer
	if err := printPackageVerification(&packageSummary, verifiedParts, true); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Test Signer <test@example.com>", "trusted (matched a pinned public key)", "ed25519 + sha256", "signed from:", "fingerprint:"} {
		if !strings.Contains(packageSummary.String(), want) {
			t.Fatalf("package verification summary lacks %q: %s", want, packageSummary.String())
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
	keyInfo, err := os.Stat(filepath.Join(os.Getenv("HOME"), ".sugyeol", "ed25519_private.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if keyInfo.Mode().Perm() != 0600 {
		t.Fatalf("private key mode = %o", keyInfo.Mode().Perm())
	}
	identityInfo, err := os.Stat(filepath.Join(os.Getenv("HOME"), ".sugyeol", "identity.json"))
	if err != nil || identityInfo.Mode().Perm() != 0600 {
		t.Fatalf("identity mode: %v, %v", identityInfo, err)
	}
}

func TestUnpackResolvesMultiplePackagePrefixes(t *testing.T) {
	t.Setenv("HOME", filepath.Join(t.TempDir(), "home"))
	initTestIdentity(t, "Prefix Signer", "prefix@example.com")
	inputDir := t.TempDir()
	alpha := filepath.Join(inputDir, "alpha")
	beta := filepath.Join(inputDir, "beta")
	if err := os.WriteFile(alpha, []byte("alpha payload"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(beta, []byte("beta payload"), 0600); err != nil {
		t.Fatal(err)
	}
	packageDir := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(packageDir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(old) }()
	if err := pack(alpha, "foo", 1<<20, false); err != nil {
		t.Fatal(err)
	}
	if err := pack(beta, "bar", 1<<20, false); err != nil {
		t.Fatal(err)
	}

	packages, err := resolveUnpackPackages([]string{"foo", "bar"})
	if err != nil {
		t.Fatal(err)
	}
	if len(packages) != 2 {
		t.Fatalf("resolved package count = %d", len(packages))
	}
	restore := t.TempDir()
	if err := run([]string{"unpack", "-o", restore, "foo", "bar"}); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"alpha": "alpha payload", "beta": "beta payload"} {
		got, err := os.ReadFile(filepath.Join(restore, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Fatalf("%s = %q", name, got)
		}
	}
	if _, err := resolveUnpackPackages([]string{"missing"}); err == nil {
		t.Fatal("missing prefix was accepted")
	}
}

func TestUnpackResolvesPartialPartNameAndCurrentDirectory(t *testing.T) {
	t.Setenv("HOME", filepath.Join(t.TempDir(), "home"))
	initTestIdentity(t, "Partial Signer", "partial@example.com")
	inputDir := t.TempDir()
	alpha := filepath.Join(inputDir, "alpha.bin")
	beta := filepath.Join(inputDir, "beta.bin")
	if err := os.WriteFile(alpha, bytes.Repeat([]byte("alpha"), 32*1024), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(beta, bytes.Repeat([]byte("beta"), 32*1024), 0600); err != nil {
		t.Fatal(err)
	}
	packageDir := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(packageDir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(old) }()
	if err := pack(alpha, "foo", 48*1024, false); err != nil {
		t.Fatal(err)
	}
	if err := pack(beta, "bar", 48*1024, false); err != nil {
		t.Fatal(err)
	}

	partial, err := resolveUnpackPackages([]string{"foo_part-000001"})
	if err != nil {
		t.Fatal(err)
	}
	if len(partial) != 1 || len(partial[0].paths) < 2 {
		t.Fatalf("partial selection resolved %#v", partial)
	}
	loose, err := resolveUnpackPackages([]string{"foo-part000000"})
	if err != nil {
		t.Fatal(err)
	}
	if len(loose) != 1 || len(loose[0].paths) != len(partial[0].paths) {
		t.Fatalf("separator-tolerant partial selection resolved %#v", loose)
	}
	all, err := resolveUnpackPackages([]string{"."})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("current-directory selection found %d packages", len(all))
	}
	common, err := resolveUnpackPackages([]string{"part-000001"})
	if err != nil {
		t.Fatal(err)
	}
	if len(common) != 2 {
		t.Fatalf("common partial selection found %d packages", len(common))
	}
}

func TestUnpackOverwriteOnlyForDifferentSetsWithSameRoot(t *testing.T) {
	t.Setenv("HOME", filepath.Join(t.TempDir(), "home"))
	initTestIdentity(t, "Overwrite Signer", "overwrite@example.com")
	firstDir, secondDir := t.TempDir(), t.TempDir()
	first, second := filepath.Join(firstDir, "same.txt"), filepath.Join(secondDir, "same.txt")
	if err := os.WriteFile(first, []byte("first"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("second"), 0600); err != nil {
		t.Fatal(err)
	}
	packageDir := t.TempDir()
	firstPrefix, secondPrefix := filepath.Join(packageDir, "foo"), filepath.Join(packageDir, "bar")
	if err := pack(first, firstPrefix, 1<<20, false); err != nil {
		t.Fatal(err)
	}
	if err := pack(second, secondPrefix, 1<<20, false); err != nil {
		t.Fatal(err)
	}
	selectors := []string{firstPrefix, secondPrefix}
	if err := unpackSelectorsWithOptions(selectors, t.TempDir(), nil, false); err == nil {
		t.Fatal("different package sets with the same restore root did not require overwrite approval")
	}
	restore := t.TempDir()
	if err := unpackSelectorsWithOptions(selectors, restore, nil, true); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(restore, "same.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "second" {
		t.Fatalf("overwritten content = %q", got)
	}
}

func TestSignatureDetailsIncludeIdentityTimeChainAndTrust(t *testing.T) {
	originalLanguage := currentLanguage
	defer func() { currentLanguage = originalLanguage }()
	setLanguage("en")
	pub, priv, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := []byte("signed manifest")
	at := time.Date(2026, 8, 21, 12, 34, 56, 789, time.UTC)
	rec, err := makeChainRecord(manifest, nil, 1, signingIdentity{Name: "Alice", Email: "alice@example.com"}, "release", priv, at)
	if err != nil {
		t.Fatal(err)
	}
	trusted := map[string]bool{publicFingerprint(pub): true}
	var output bytes.Buffer
	printSignatureRecordDetails(&output, []signatureRecord{rec}, []ed25519.PublicKey{pub}, 1, trusted, true)
	text := output.String()
	for _, want := range []string{
		"Alice <alice@example.com>", "release", at.Format(time.RFC3339Nano), "ed25519",
		hex.EncodeToString(pub), publicFingerprint(pub), rec.ManifestSHA256, rec.Salt,
		recordDigest(rec), rec.Signature, "(genesis signature)", "trusted (matched a pinned public key)",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("signature details lack %q: %s", want, text)
		}
	}
	pub2, priv2, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rec2, err := makeChainRecord(manifest, &rec, 2, signingIdentity{Name: "Bob", Email: "bob@example.com"}, "review", priv2, at.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	output.Reset()
	printSignatureRecordDetails(&output, []signatureRecord{rec, rec2}, []ed25519.PublicKey{pub, pub2}, 2, trusted, true)
	for _, want := range []string{"signature 2/2", "Bob <bob@example.com>", recordDigest(rec), "chain-valid, but this signer is not directly pinned"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("chain signature details lack %q: %s", want, output.String())
		}
	}
	badTime := rec
	badTime.SignedAt = time.Time{}
	if _, err := verifySignatureChain(manifest, []signatureRecord{badTime}); err == nil || !strings.Contains(err.Error(), "signing time") {
		t.Fatalf("missing signing time was not rejected: %v", err)
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
	if _, err := os.Stat(filepath.Join(os.Getenv("HOME"), ".sugyeol", "ed25519_private.pem")); !os.IsNotExist(err) {
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
	parts, _ := filepath.Glob(prefix + "_part-*.zip")
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
	parts, _ := filepath.Glob(prefix + "_part-*.zip")
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

func TestPackCompressionAndShortFlags(t *testing.T) {
	t.Setenv("HOME", filepath.Join(t.TempDir(), "home"))
	initTestIdentity(t, "Compression Signer", "compression@example.com")
	input := filepath.Join(t.TempDir(), "compressible.bin")
	data := bytes.Repeat([]byte("sugyeol-compression-test\x00"), 80000)
	if err := os.WriteFile(input, data, 0600); err != nil {
		t.Fatal(err)
	}
	prefix := filepath.Join(t.TempDir(), "compressed")
	const maxSize = int64(256 * 1024)
	if err := run([]string{"pack", "-s", "256KiB", "-o", prefix, "-x=false", "-c", "highest", input}); err != nil {
		t.Fatal(err)
	}
	parts, _ := filepath.Glob(prefix + "_part-*.zip")
	if len(parts) == 0 {
		t.Fatal("no compressed parts")
	}
	verified, err := verifyParts(parts, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range verified {
		if p.m.Compression != "deflate" || p.m.CompressionLevel != 9 {
			t.Fatalf("compression manifest = %q level %d", p.m.Compression, p.m.CompressionLevel)
		}
		st, err := os.Stat(p.path)
		if err != nil || st.Size() > maxSize {
			t.Fatalf("compressed part size: %v, %v", st, err)
		}
	}
	restore := t.TempDir()
	if err := run(append([]string{"unpack", "-o", restore}, parts...)); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(restore, "compressible.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("compressed round trip differs")
	}
	randomInput := filepath.Join(t.TempDir(), "incompressible.bin")
	randomData := make([]byte, 2*1024*1024)
	if _, err := crand.Read(randomData); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(randomInput, randomData, 0600); err != nil {
		t.Fatal(err)
	}
	randomPrefix := filepath.Join(t.TempDir(), "incompressible")
	highest, _ := parseCompression("highest")
	if err := packWithOptions(randomInput, randomPrefix, maxSize, false, nil, highest); err != nil {
		t.Fatal(err)
	}
	randomParts, _ := filepath.Glob(randomPrefix + "_part-*.zip")
	if _, err := verifyParts(randomParts, false); err != nil {
		t.Fatal(err)
	}
	for _, part := range randomParts {
		st, err := os.Stat(part)
		if err != nil || st.Size() > maxSize {
			t.Fatalf("incompressible part size: %v, %v", st, err)
		}
	}
	for _, value := range []string{"none", "fastest", "default", "highest", "0", "1", "5", "9"} {
		if _, err := parseCompression(value); err != nil {
			t.Fatalf("parseCompression(%q): %v", value, err)
		}
	}
	if _, err := parseCompression("10"); err == nil {
		t.Fatal("invalid compression level was accepted")
	}
}

func TestEncryptedPackRoundTripAndWrongPassword(t *testing.T) {
	t.Setenv("HOME", filepath.Join(t.TempDir(), "home"))
	initTestIdentity(t, "Crypto Signer", "crypto@example.com")
	input := filepath.Join(t.TempDir(), "encrypted.bin")
	data := bytes.Repeat([]byte("high-speed authenticated encryption\x00"), 160000)
	if err := os.WriteFile(input, data, 0600); err != nil {
		t.Fatal(err)
	}
	prefix := filepath.Join(t.TempDir(), "encrypted")
	password := []byte("correct horse battery staple")
	const maxSize = int64(6 * 1024 * 1024)
	if err := packWithPassword(input, prefix, maxSize, false, password); err != nil {
		t.Fatal(err)
	}
	parts, _ := filepath.Glob(prefix + "_part-*.zip")
	if len(parts) == 0 {
		t.Fatal("no encrypted parts")
	}
	verified, err := verifyParts(parts, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range verified {
		if p.m.Encryption != encryptionName || p.m.KDF != kdfName || p.m.StoredSize != encryptedStoredSize(p.m.PayloadSize) {
			t.Fatal("encrypted manifest fields are invalid")
		}
		st, err := os.Stat(p.path)
		if err != nil || st.Size() > maxSize {
			t.Fatalf("encrypted part size: %v, %v", st, err)
		}
	}
	restore := t.TempDir()
	if err := unpackWithPassword(parts, restore, append([]byte(nil), password...)); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(restore, "encrypted.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("decrypted data differs")
	}
	if err := unpackWithPassword(parts, t.TempDir(), []byte("definitely wrong password")); err == nil {
		t.Fatal("wrong password was accepted")
	}
	literalPrefix := filepath.Join(t.TempDir(), "literal-password")
	if err := run([]string{"pack", "-e", "-P", "literal-password-value", "-s", "6MiB", "-o", literalPrefix, input}); err != nil {
		t.Fatal(err)
	}
	literalParts, _ := filepath.Glob(literalPrefix + "_part-*.zip")
	literalRestore := t.TempDir()
	literalArgs := []string{"unpack", "-P", "literal-password-value", "-o", literalRestore}
	literalArgs = append(literalArgs, literalParts...)
	if err := run(literalArgs); err != nil {
		t.Fatal(err)
	}
	literalData, err := os.ReadFile(filepath.Join(literalRestore, "encrypted.bin"))
	if err != nil || !bytes.Equal(literalData, data) {
		t.Fatal("literal password CLI round trip differs")
	}
	if err := run([]string{"pack", "-e", "-P", "literal-password-value", "-p", filepath.Join(t.TempDir(), "password"), "-o", filepath.Join(t.TempDir(), "invalid"), input}); err == nil {
		t.Fatal("password and password-file were accepted together")
	}
}

func TestPackByExactPartCount(t *testing.T) {
	t.Setenv("HOME", filepath.Join(t.TempDir(), "home"))
	initTestIdentity(t, "Count Splitter", "count@example.com")
	input := filepath.Join(t.TempDir(), "count.bin")
	data := bytes.Repeat([]byte("exact-count-split"), 10000)
	if err := os.WriteFile(input, data, 0600); err != nil {
		t.Fatal(err)
	}
	prefix := filepath.Join(t.TempDir(), "counted")
	if err := run([]string{"pack", "-n", "7", "-o", prefix, "-x=false", "-c", "highest", input}); err != nil {
		t.Fatal(err)
	}
	parts, _ := filepath.Glob(prefix + "_part-*.zip")
	if len(parts) != 7 {
		t.Fatalf("parts = %d, want 7", len(parts))
	}
	verified, err := verifyParts(parts, false)
	if err != nil {
		t.Fatal(err)
	}
	minSize, maxSize := verified[0].m.PayloadSize, verified[0].m.PayloadSize
	for _, part := range verified[1:] {
		if part.m.PayloadSize < minSize {
			minSize = part.m.PayloadSize
		}
		if part.m.PayloadSize > maxSize {
			maxSize = part.m.PayloadSize
		}
	}
	if maxSize-minSize > 1 {
		t.Fatalf("count split is not balanced: min=%d max=%d", minSize, maxSize)
	}
	restore := t.TempDir()
	if err := unpack(parts, restore); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(restore, "count.bin"))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("count split round trip differs")
	}
	if err := run([]string{"pack", "-n", "2", "-s", "1MiB", "-o", filepath.Join(t.TempDir(), "invalid"), input}); err == nil {
		t.Fatal("size and parts were accepted together")
	}
	if err := run([]string{"pack", "-n", "0", "-o", filepath.Join(t.TempDir(), "invalid-zero"), input}); err == nil {
		t.Fatal("zero part count was accepted")
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
	if err := countersignCommand([]string{"-source", source, "-label", "reviewer", "-pubkey", pub1Path, meta}); err != nil {
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
	if err := countersignCommand([]string{"-source", source, "-pubkey", pub1Path, meta}); err == nil {
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
	if err := countersignCommand([]string{"-source", source, "-pubkey", pub1Path, meta}); err == nil {
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
	if err != nil || name != "sugyeol_1.0.0_linux_x86_64" {
		t.Fatalf("asset = %q, %v", name, err)
	}
}

func TestContainerImageSignAndVerify(t *testing.T) {
	t.Setenv("HOME", filepath.Join(t.TempDir(), "home"))
	initTestIdentity(t, "Image Signer", "image@example.com")
	config := []byte(`{"architecture":"amd64","os":"linux"}`)
	layer := []byte("small compressed layer bytes")
	configSum, layerSum := sha256.Sum256(config), sha256.Sum256(layer)
	configDigest := "sha256:" + hex.EncodeToString(configSum[:])
	layerDigest := "sha256:" + hex.EncodeToString(layerSum[:])
	manifest := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":%q,"size":%d},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":%q,"size":%d}]}`, configDigest, len(config), layerDigest, len(layer)))
	manifestSum := sha256.Sum256(manifest)
	manifestDigest := "sha256:" + hex.EncodeToString(manifestSum[:])
	index := []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":%q,"size":%d,"platform":{"os":"linux","architecture":"amd64"}}]}`, manifestDigest, len(manifest)))
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" && r.Header.Get("Authorization") != "Bearer test-token" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+server.URL+`/token",service="test",scope="repository:team/app:pull"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/token":
			fmt.Fprint(w, `{"token":"test-token"}`)
		case "/v2/team/app/manifests/latest":
			d := sha256.Sum256(index)
			w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
			w.Header().Set("Docker-Content-Digest", "sha256:"+hex.EncodeToString(d[:]))
			w.Write(index)
		case "/v2/team/app/manifests/" + manifestDigest:
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			w.Header().Set("Docker-Content-Digest", manifestDigest)
			w.Write(manifest)
		case "/v2/team/app/blobs/" + configDigest:
			w.Write(config)
		case "/v2/team/app/blobs/" + layerDigest:
			w.Write(layer)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	imageRef := strings.TrimPrefix(server.URL, "http://") + "/team/app:latest"
	archive := filepath.Join(t.TempDir(), "image.oci.tgz")
	meta := filepath.Join(t.TempDir(), "image.meta")
	if err := imagePullCommand([]string{"-o", archive, "-z", "-S", "-m", meta, "-l", "release", "-t", "alpine:260904", imageRef}); err != nil {
		t.Fatal(err)
	}
	subject, err := inspectContainerArchive(archive)
	if err != nil {
		t.Fatal(err)
	}
	if subject.ArchiveFormat != "oci-image-layout" || !subject.DockerCompatible || subject.Compression != "gzip" || len(subject.RootDescriptors) != 1 {
		t.Fatalf("unexpected local image subject: %+v", subject)
	}
	wantReference := "alpine:260904"
	if len(subject.References) != 1 || subject.References[0] != wantReference {
		t.Fatalf("Docker-compatible reference = %v, want %s", subject.References, wantReference)
	}
	annotations := subject.RootDescriptors[0].Annotations
	if annotations["io.containerd.image.name"] != "docker.io/library/alpine:260904" || annotations["org.opencontainers.image.ref.name"] != "260904" {
		t.Fatalf("runtime import annotations = %v", annotations)
	}
	_, pub, _, err := loadSigningIdentity()
	if err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(t.TempDir(), "image-signer.pem")
	if err := os.WriteFile(pubPath, pub, 0644); err != nil {
		t.Fatal(err)
	}
	if err := imageVerifyCommand([]string{"-pubkey", pubPath, archive, meta}); err != nil {
		t.Fatal(err)
	}
	metaBytes, err := os.ReadFile(meta)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(metaBytes, []byte("docker_compatible")) {
		t.Fatal("derived compatibility flag leaked into signed metadata")
	}
	f, err := os.OpenFile(archive, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("changed")); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := imageVerifyCommand([]string{"-pubkey", pubPath, archive, meta}); err == nil {
		t.Fatal("changed local archive verified")
	}
}

func TestDockerSaveArchiveInspection(t *testing.T) {
	t.Setenv("HOME", filepath.Join(t.TempDir(), "home"))
	initTestIdentity(t, "Docker Archive Signer", "docker-archive@example.com")
	archive := filepath.Join(t.TempDir(), "docker-image.tar")
	f, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(f)
	entries := map[string][]byte{
		"config.json":     []byte(`{"architecture":"amd64","os":"linux"}`),
		"layer/layer.tar": []byte("layer"),
		"manifest.json":   []byte(`[{"Config":"config.json","RepoTags":["team/app:latest"],"Layers":["layer/layer.tar"]}]`),
	}
	for _, name := range []string{"config.json", "layer/layer.tar", "manifest.json"} {
		data := entries[name]
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	subject, err := inspectContainerArchive(archive)
	if err != nil {
		t.Fatal(err)
	}
	if subject.ArchiveFormat != "docker-save" || len(subject.References) != 1 || subject.References[0] != "team/app:latest" {
		t.Fatalf("unexpected docker archive subject: %+v", subject)
	}
	meta := filepath.Join(t.TempDir(), "docker.image.meta")
	if err := imageSignCommand([]string{"-o", meta, archive}); err != nil {
		t.Fatal(err)
	}
	_, pub, _, err := loadSigningIdentity()
	if err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(t.TempDir(), "docker.pem")
	if err := os.WriteFile(pubPath, pub, 0644); err != nil {
		t.Fatal(err)
	}
	if err := imageVerifyCommand([]string{"-k", pubPath, archive, meta}); err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv("HOME", filepath.Join(t.TempDir(), "reviewer-home")); err != nil {
		t.Fatal(err)
	}
	initTestIdentity(t, "Docker Archive Reviewer", "docker-reviewer@example.com")
	_, reviewerPub, _, err := loadSigningIdentity()
	if err != nil {
		t.Fatal(err)
	}
	reviewerPath := filepath.Join(t.TempDir(), "reviewer.pem")
	if err := os.WriteFile(reviewerPath, reviewerPub, 0644); err != nil {
		t.Fatal(err)
	}
	if err := imageCountersignCommand([]string{"-k", pubPath, "-l", "review", archive, meta}); err != nil {
		t.Fatal(err)
	}
	if err := imageVerifyCommand([]string{"-n", "2", "-k", pubPath, "-k", reviewerPath, archive, meta}); err != nil {
		t.Fatal(err)
	}
}

func TestImageSPDXGenerationAndSourceBinding(t *testing.T) {
	t.Setenv("HOME", filepath.Join(t.TempDir(), "home"))
	initTestIdentity(t, "SBOM Scanner", "scanner@example.com")
	makeLayer := func(entries map[string][]byte) []byte {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		names := make([]string, 0, len(entries))
		for name := range entries {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			data := entries[name]
			if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(data))}); err != nil {
				t.Fatal(err)
			}
			if _, err := tw.Write(data); err != nil {
				t.Fatal(err)
			}
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	layer1 := makeLayer(map[string][]byte{
		"var/lib/dpkg/status": []byte("Package: libc6\nStatus: install ok installed\nVersion: 2.39-1\nArchitecture: amd64\n\n"),
		"deleted.txt":         []byte("old"),
	})
	layer2 := makeLayer(map[string][]byte{
		".wh.deleted.txt":                          {},
		"app/requirements.txt":                     []byte("requests==2.32.3\n"),
		"app/node_modules/express/package.json":    []byte(`{"name":"express","version":"4.21.2","license":"MIT"}`),
		"opt/pyenv/versions/3.12.4/bin/python3.12": []byte("python-binary"),
		"opt/pyenv/versions/3.12.4/lib/python3.12/site-packages/flask-3.0.3.dist-info/METADATA": []byte("Name: Flask\nVersion: 3.0.3\nLicense: BSD-3-Clause\n"),
		"usr/local/include/node/node_version.h":                                                 []byte("#define NODE_MAJOR_VERSION 22\n#define NODE_MINOR_VERSION 14\n#define NODE_PATCH_VERSION 0\n"),
		"etc/os-release":                                                                        []byte("ID=debian\nVERSION_ID=12\n"),
	})
	archive := filepath.Join(t.TempDir(), "packages.tar")
	f, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(f)
	manifest := []byte(`[{"Config":"config.json","RepoTags":["test:latest"],"Layers":["l1.tar","l2.tar"]}]`)
	for _, entry := range []struct {
		name string
		data []byte
	}{{"config.json", []byte(`{"architecture":"amd64","os":"linux"}`)}, {"l1.tar", layer1}, {"l2.tar", layer2}, {"manifest.json", manifest}} {
		if err := tw.WriteHeader(&tar.Header{Name: entry.name, Mode: 0644, Size: int64(len(entry.data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "packages.spdx.json")
	if err := generateImageSBOM(archive, out, true, "security-scan"); err != nil {
		t.Fatal(err)
	}
	if err := verifyImageSBOMBinding(archive, out); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"spdxVersion": "SPDX-2.3"`, `"name": "libc6"`, `"name": "requests"`, `"name": "express"`, `"name": "Flask"`, `"name": "python"`, `"name": "node"`} {
		if !bytes.Contains(b, []byte(want)) {
			t.Errorf("SPDX output missing %s", want)
		}
	}
	if bytes.Contains(b, []byte("deleted.txt")) {
		t.Fatal("whiteout-deleted file appeared in SBOM")
	}
	_, publicPEM, _, err := loadSigningIdentity()
	if err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(t.TempDir(), "scanner.pem")
	if err := os.WriteFile(pubPath, publicPEM, 0644); err != nil {
		t.Fatal(err)
	}
	if err := imageSBOMVerifyCommand([]string{"-k", pubPath, archive, out, out + ".meta"}); err != nil {
		t.Fatal(err)
	}
	archiveBytes, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(archive, append(archiveBytes, 0), 0644); err != nil {
		t.Fatal(err)
	}
	if err := verifyImageSBOMBinding(archive, out); err == nil {
		t.Fatal("SBOM verified against a changed archive")
	}
}

func TestSBOMLanguageAndRuntimeCatalogers(t *testing.T) {
	files := []sbomFile{
		{Path: "app/node_modules/@scope/tool/package.json", Data: []byte(`{"name":"@scope/tool","version":"2.1.0","license":"MIT"}`)},
		{Path: "app/Pipfile.lock", Data: []byte(`{"default":{"django":{"version":"==5.1.1"}}}`)},
		{Path: "app/poetry.lock", Data: []byte("[[package]]\nname = \"httpx\"\nversion = \"0.27.2\"\n")},
		{Path: "app/composer.lock", Data: []byte(`{"packages":[{"name":"symfony/console","version":"v7.1.0","license":["MIT"]}]}`)},
		{Path: "app/Gemfile.lock", Data: []byte("GEM\n  specs:\n    rack (3.1.0)\n")},
		{Path: "app/project.assets.json", Data: []byte(`{"libraries":{"Newtonsoft.Json/13.0.3":{}}}`)},
		{Path: "app/Package.resolved", Data: []byte(`{"pins":[{"identity":"swift-log","state":{"version":"1.6.1"}}]}`)},
		{Path: "app/pubspec.lock", Data: []byte("packages:\n  collection:\n    dependency: transitive\n    version: \"1.19.0\"\n")},
		{Path: "opt/conda/conda-meta/numpy.json", Data: []byte(`{"name":"numpy","version":"2.1.0","license":"BSD-3-Clause"}`)},
	}
	packages, _, _, warnings := catalogSBOMPackages(files)
	if len(warnings) != 0 {
		t.Fatalf("unexpected catalog warnings: %v", warnings)
	}
	got := map[string]string{}
	for _, p := range packages {
		got[p.Name] = p.Version
	}
	for name, version := range map[string]string{"@scope/tool": "2.1.0", "django": "5.1.1", "httpx": "0.27.2", "symfony/console": "v7.1.0", "rack": "3.1.0", "Newtonsoft.Json": "13.0.3", "swift-log": "1.6.1", "collection": "1.19.0", "numpy": "2.1.0"} {
		if got[name] != version {
			t.Errorf("package %s = %q, want %q (all: %#v)", name, got[name], version, got)
		}
	}
}

func TestGenerateMultiPlatformSBOMs(t *testing.T) {
	makeTestLayer := func(entries map[string][]byte) []byte {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		for name, data := range entries {
			if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(data))}); err != nil {
				t.Fatal(err)
			}
			if _, err := tw.Write(data); err != nil {
				t.Fatal(err)
			}
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	amdLayer := makeTestLayer(map[string][]byte{"etc/os-release": []byte("ID=alpine\nVERSION_ID=3.20\n"), "amd64.txt": []byte("amd64")})
	armLayer := makeTestLayer(map[string][]byte{"etc/os-release": []byte("ID=alpine\nVERSION_ID=3.20\n"), "arm64.txt": []byte("arm64")})
	archive := filepath.Join(t.TempDir(), "multi.tar")
	f, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(f)
	manifest := []byte(`[{"Config":"amd.json","RepoTags":["multi:latest"],"Layers":["amd.tar"]},{"Config":"arm.json","RepoTags":["multi:latest"],"Layers":["arm.tar"]}]`)
	entries := []struct {
		name string
		data []byte
	}{
		{"amd.json", []byte(`{"architecture":"amd64","os":"linux"}`)},
		{"arm.json", []byte(`{"architecture":"arm64","os":"linux","variant":"v8"}`)},
		{"amd.tar", amdLayer}, {"arm.tar", armLayer}, {"manifest.json", manifest},
	}
	for _, entry := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: entry.name, Mode: 0644, Size: int64(len(entry.data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "sboms")
	if err := generateImageSBOMs(archive, out, false, "sbom", "linux/amd64", true); err != nil {
		t.Fatal(err)
	}
	for file, marker := range map[string]string{"linux-amd64.spdx.json": "amd64.txt", "linux-arm64-v8.spdx.json": "arm64.txt"} {
		b, err := os.ReadFile(filepath.Join(out, file))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(b, []byte(marker)) || !bytes.Contains(b, []byte(`platform: linux/`)) {
			t.Fatalf("%s lacks platform-specific content", file)
		}
	}
}

func TestImageLayerMediaTypesExcludeAttestations(t *testing.T) {
	image := ociManifest{Layers: []ociDescriptor{{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip"}}}
	if !hasOnlyImageLayers(image) {
		t.Fatal("OCI gzip image layer was rejected")
	}
	attestation := ociManifest{Layers: []ociDescriptor{{MediaType: "application/vnd.in-toto+json"}}}
	if hasOnlyImageLayers(attestation) {
		t.Fatal("in-toto attestation was accepted as a runnable image layer")
	}
}

func TestParseImageReference(t *testing.T) {
	ref, err := parseImageReference("ubuntu:24.04")
	if err != nil {
		t.Fatal(err)
	}
	if ref.Registry != "registry-1.docker.io" || ref.Repository != "library/ubuntu" || ref.Identifier != "24.04" {
		t.Fatalf("unexpected ref: %+v", ref)
	}
	if _, err := parseImageReference("example.com/team/app@sha256:bad"); err == nil {
		t.Fatal("invalid digest accepted")
	}
	source, _ := parseImageReference("example.com/team/app:latest")
	rewritten, err := parseArchiveImageReference("260904", source)
	if err != nil || rewritten.Repository != "team/app" || rewritten.Identifier != "260904" {
		t.Fatalf("bare archive tag rewrite = %+v, %v", rewritten, err)
	}
	rewritten, err = parseArchiveImageReference("alpine:260904", source)
	if err != nil || rewritten.Repository != "library/alpine" || rewritten.Identifier != "260904" {
		t.Fatalf("named archive tag rewrite = %+v, %v", rewritten, err)
	}
}

func BenchmarkEncryptedPayload64MiB(b *testing.B) {
	plain := bytes.Repeat([]byte{0x5a}, 64*1024*1024)
	m := manifest{SetID: "00112233445566778899aabbccddeeff", Part: 1, TotalParts: 1, PayloadSize: int64(len(plain))}
	master := bytes.Repeat([]byte{0x42}, 32)
	nonce := "00112233445566778899aabb"
	b.SetBytes(int64(len(plain)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := encryptPayload(io.Discard, bytes.NewReader(plain), m, master, nonce, sha256.New(), sha256.New()); err != nil {
			b.Fatal(err)
		}
	}
}
