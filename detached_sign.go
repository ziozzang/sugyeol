package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const detachedFormat = "sugyeol-detached-signature"

type signedEntry struct {
	Path   string `json:"path"`
	Type   string `json:"type"`
	Size   int64  `json:"size,omitempty"`
	Mode   uint32 `json:"mode"`
	SHA256 string `json:"sha256,omitempty"`
}
type signedManifest struct {
	Format   string        `json:"format"`
	Version  int           `json:"version"`
	RootName string        `json:"root_name"`
	Entries  []signedEntry `json:"entries"`
}
type signatureRecord struct {
	Version              int       `json:"version"`
	Index                int       `json:"index"`
	Algorithm            string    `json:"algorithm"`
	SignerName           string    `json:"signer_name"`
	SignerEmail          string    `json:"signer_email"`
	SignerLabel          string    `json:"signer_label,omitempty"`
	PublicKey            string    `json:"public_key"`
	ManifestSHA256       string    `json:"manifest_sha256"`
	PreviousRecordSHA256 string    `json:"previous_record_sha256,omitempty"`
	SignedAt             time.Time `json:"signed_at"`
	Salt                 string    `json:"salt"`
	Signature            string    `json:"signature"`
}
type signatureBundle struct {
	Format   string            `json:"format"`
	Version  int               `json:"version"`
	Manifest signedManifest    `json:"manifest"`
	Records  []signatureRecord `json:"records"`
}

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func signCommand(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	out := fs.String("out", "", "detached metadata output (default: <source>.meta)")
	label := fs.String("label", "", "optional signed role/purpose label")
	fs.StringVar(out, "o", "", "detached metadata output (default: <source>.meta)")
	fs.StringVar(label, "l", "", "optional signed role/purpose label")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: sugyeol sign [-out file.meta] <file|directory>")
	}
	source := fs.Arg(0)
	if *out == "" {
		*out = strings.TrimRight(source, string(filepath.Separator)) + ".meta"
	}
	sourceAbs, err := filepath.Abs(source)
	if err != nil {
		return err
	}
	info, err := os.Lstat(sourceAbs)
	if err != nil {
		return err
	}
	outAbs, err := filepath.Abs(*out)
	if err != nil {
		return err
	}
	if info.IsDir() && strings.HasPrefix(outAbs, sourceAbs+string(filepath.Separator)) {
		return fmt.Errorf("metadata sidecar must be outside the directory being signed")
	}
	manifestBytes, signedContent, err := buildSignedManifest(source)
	if err != nil {
		return err
	}
	priv, _, identity, err := loadSigningIdentity()
	if err != nil {
		return err
	}
	pub := priv.Public().(ed25519.PublicKey)
	rec, err := makeChainRecord(manifestBytes, nil, 1, identity, *label, priv, time.Now().UTC())
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(signatureBundle{Format: detachedFormat, Version: 2, Manifest: signedContent, Records: []signatureRecord{rec}}, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*out, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	fmt.Printf(tr("signed"), source, *out)
	fmt.Printf(tr("public_key"), hex.EncodeToString(pub))
	fmt.Printf(tr("fingerprint"), publicFingerprint(pub))
	return nil
}

func keyCommand(args []string) error {
	if len(args) > 0 && args[0] == "init" {
		fs := flag.NewFlagSet("key init", flag.ContinueOnError)
		name := fs.String("name", "", "signer name")
		email := fs.String("email", "", "signer email")
		fs.StringVar(name, "n", "", "signer name")
		fs.StringVar(email, "e", "", "signer email")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		id, err := initializeIdentity(*name, *email)
		if err != nil {
			return err
		}
		fmt.Printf("signing identity initialized\nname: %s\nemail: %s\nfingerprint: %s\n", id.Name, id.Email, id.Fingerprint)
		return nil
	}
	fs := flag.NewFlagSet("key", flag.ContinueOnError)
	out := fs.String("out", "", "write the public key PEM to this path")
	fs.StringVar(out, "o", "", "write the public key PEM to this path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	priv, pemBytes, id, err := loadSigningIdentity()
	if err != nil {
		return err
	}
	pub := priv.Public().(ed25519.PublicKey)
	fmt.Printf("name: %s\nemail: %s\n", id.Name, id.Email)
	if *out != "" {
		if err := os.WriteFile(*out, pemBytes, 0644); err != nil {
			return err
		}
	}
	fmt.Printf(tr("public_key"), hex.EncodeToString(pub))
	fmt.Printf(tr("fingerprint"), publicFingerprint(pub))
	if *out != "" {
		fmt.Printf(tr("public_key_pem"), *out)
	}
	return nil
}

func countersignCommand(args []string) error {
	fs := flag.NewFlagSet("countersign", flag.ContinueOnError)
	source := fs.String("source", "", "source file/directory (default: root_name in metadata)")
	out := fs.String("out", "", "output metadata (default: replace the input metadata atomically)")
	label := fs.String("label", "", "optional signed role/purpose label")
	var trustedKeys stringList
	fs.Var(&trustedKeys, "pubkey", "trusted existing signer key (repeatable; at least one required)")
	minPrior := fs.Int("min-signatures", 1, "minimum existing signatures required")
	fs.StringVar(source, "s", "", "source file/directory (default: root_name in metadata)")
	fs.StringVar(out, "o", "", "output metadata (default: replace the input metadata atomically)")
	fs.StringVar(label, "l", "", "optional signed role/purpose label")
	fs.Var(&trustedKeys, "k", "trusted existing signer key (repeatable; at least one required)")
	fs.IntVar(minPrior, "n", 1, "minimum existing signatures required")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: sugyeol countersign [-source path] [-out copy.meta] -pubkey trusted.pem <source.meta>")
	}
	input := fs.Arg(0)
	bundle, manifestBytes, err := loadSignatureBundle(input)
	if err != nil {
		return err
	}
	pubs, err := verifySignatureChain(manifestBytes, bundle.Records)
	if err != nil {
		return err
	}
	if len(trustedKeys) == 0 {
		return fmt.Errorf("countersigning requires at least one trusted existing signer via -pubkey")
	}
	if err := checkSignaturePolicy(pubs, trustedKeys, *minPrior); err != nil {
		return err
	}
	actualSource := *source
	if actualSource == "" {
		actualSource = bundle.Manifest.RootName
	}
	actualManifest, _, err := buildSignedManifest(actualSource)
	if err != nil {
		return err
	}
	if !bytes.Equal(actualManifest, manifestBytes) {
		return fmt.Errorf("source does not match the signed SHA-256 manifest")
	}
	priv, _, identity, err := loadSigningIdentity()
	if err != nil {
		return err
	}
	previous := &bundle.Records[len(bundle.Records)-1]
	rec, err := makeChainRecord(manifestBytes, previous, len(bundle.Records)+1, identity, *label, priv, time.Now().UTC())
	if err != nil {
		return err
	}
	bundle.Records = append(bundle.Records, rec)
	destination := *out
	if destination == "" {
		destination = input
	}
	if err := writeSignatureBundle(destination, bundle); err != nil {
		return err
	}
	pub := priv.Public().(ed25519.PublicKey)
	fmt.Printf("countersignature %d added: %s\n", len(bundle.Records), destination)
	fmt.Printf(tr("public_key"), hex.EncodeToString(pub))
	fmt.Printf(tr("fingerprint"), publicFingerprint(pub))
	return nil
}

func loadSignatureBundle(path string) (signatureBundle, []byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return signatureBundle{}, nil, err
	}
	var bundle signatureBundle
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&bundle); err != nil {
		return signatureBundle{}, nil, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return signatureBundle{}, nil, fmt.Errorf("trailing data in metadata")
	}
	if bundle.Format != detachedFormat || bundle.Version != 2 {
		return signatureBundle{}, nil, fmt.Errorf("unsupported detached signature format")
	}
	manifestBytes, err := json.MarshalIndent(bundle.Manifest, "", "  ")
	return bundle, manifestBytes, err
}

func writeSignatureBundle(path string, bundle signatureBundle) error {
	b, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".sugyeol-meta-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		tmp.Close()
		if !ok {
			os.Remove(name)
		}
	}()
	if _, err = tmp.Write(b); err == nil {
		err = tmp.Sync()
	}
	if err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Chmod(name, 0644); err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	ok = true
	return nil
}

func buildSignedManifest(source string) ([]byte, signedManifest, error) {
	abs, err := filepath.Abs(source)
	if err != nil {
		return nil, signedManifest{}, err
	}
	rootInfo, err := os.Lstat(abs)
	if err != nil {
		return nil, signedManifest{}, err
	}
	if !rootInfo.IsDir() && !rootInfo.Mode().IsRegular() {
		return nil, signedManifest{}, fmt.Errorf("only regular files and directories can be signed")
	}
	m := signedManifest{Format: "sugyeol-sha256-manifest", Version: 1, RootName: rootInfo.Name()}
	parent := filepath.Dir(abs)
	err = filepath.Walk(abs, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("unsupported entry: %s", path)
		}
		rel, err := filepath.Rel(parent, path)
		if err != nil {
			return err
		}
		e := signedEntry{Path: filepath.ToSlash(rel), Mode: uint32(info.Mode().Perm())}
		if info.IsDir() {
			e.Type = "directory"
		} else {
			e.Type, e.Size = "file", info.Size()
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			h := sha256.New()
			_, copyErr := io.Copy(h, f)
			closeErr := f.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
			e.SHA256 = hex.EncodeToString(h.Sum(nil))
		}
		m.Entries = append(m.Entries, e)
		return nil
	})
	if err != nil {
		return nil, signedManifest{}, err
	}
	sort.Slice(m.Entries, func(i, j int) bool { return m.Entries[i].Path < m.Entries[j].Path })
	b, err := json.MarshalIndent(m, "", "  ")
	return b, m, err
}

func verifyDetached(signaturePath, source string, pinnedPaths []string, minSignatures int) error {
	bundle, canonical, err := loadSignatureBundle(signaturePath)
	if err != nil {
		return err
	}
	stored := bundle.Manifest
	if source == "" {
		source = stored.RootName
	}
	actual, _, err := buildSignedManifest(source)
	if err != nil {
		return err
	}
	if !bytes.Equal(actual, canonical) {
		return fmt.Errorf("SHA-256 manifest mismatch: content was added, removed, renamed, or changed")
	}
	pubs, err := verifySignatureChain(canonical, bundle.Records)
	if err != nil {
		return err
	}
	if err := checkSignaturePolicy(pubs, pinnedPaths, minSignatures); err != nil {
		return err
	}
	fmt.Printf(tr("signature_ok"), source)
	for i, rec := range bundle.Records {
		fmt.Printf("signature %d/%d\n", i+1, len(bundle.Records))
		who := rec.SignerName + " <" + rec.SignerEmail + ">"
		if rec.SignerLabel != "" {
			who += " [" + rec.SignerLabel + "]"
		}
		fmt.Printf(tr("signer"), who)
		fmt.Printf(tr("signed_at"), rec.SignedAt.Format(time.RFC3339))
		fmt.Printf(tr("fingerprint"), publicFingerprint(pubs[i]))
	}
	if len(pinnedPaths) == 0 {
		fmt.Fprintln(os.Stderr, tr("unpinned_warning"))
	}
	return nil
}

func checkSignaturePolicy(pubs []ed25519.PublicKey, pinnedPaths []string, minimum int) error {
	if minimum < 1 {
		minimum = 1
	}
	if len(pubs) < minimum {
		return fmt.Errorf("signature policy requires %d signatures, found %d", minimum, len(pubs))
	}
	for _, path := range pinnedPaths {
		pinned, err := loadPinnedPublicKey(path)
		if err != nil {
			return err
		}
		found := false
		for _, pub := range pubs {
			if pub.Equal(pinned) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("trusted public key %s is not present in the signature chain", path)
		}
	}
	return nil
}

func makeChainRecord(manifest []byte, previous *signatureRecord, index int, identity signingIdentity, label string, priv ed25519.PrivateKey, at time.Time) (signatureRecord, error) {
	d := sha256.Sum256(manifest)
	salt, err := randomHex(16)
	if err != nil {
		return signatureRecord{}, err
	}
	rec := signatureRecord{Version: 1, Index: index, Algorithm: "ed25519", SignerName: identity.Name, SignerEmail: identity.Email, SignerLabel: label,
		PublicKey: hex.EncodeToString(priv.Public().(ed25519.PublicKey)), ManifestSHA256: hex.EncodeToString(d[:]), SignedAt: at.UTC(), Salt: salt}
	if previous != nil {
		rec.PreviousRecordSHA256 = recordDigest(*previous)
	}
	rec.Signature = hex.EncodeToString(ed25519.Sign(priv, chainPreimage(rec)))
	return rec, nil
}

func chainPreimage(rec signatureRecord) []byte {
	return []byte("sugyeol-signature-chain-v1\nindex: " + strconv.Itoa(rec.Index) + "\nalgorithm: " + rec.Algorithm + "\nsigner_name: " + strconv.Quote(rec.SignerName) + "\nsigner_email: " + strconv.Quote(rec.SignerEmail) + "\nsigner_label: " + strconv.Quote(rec.SignerLabel) + "\nsigned_at: " + rec.SignedAt.UTC().Format(time.RFC3339Nano) + "\nsalt: " + rec.Salt + "\npublic_key: " + rec.PublicKey + "\nmanifest_sha256: " + rec.ManifestSHA256 + "\nprevious_record_sha256: " + rec.PreviousRecordSHA256 + "\n")
}

func recordDigest(rec signatureRecord) string {
	b, _ := json.Marshal(rec)
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}

func verifySignatureChain(manifest []byte, records []signatureRecord) ([]ed25519.PublicKey, error) {
	if len(records) == 0 {
		return nil, fmt.Errorf("signature chain is empty")
	}
	d := sha256.Sum256(manifest)
	manifestDigest := hex.EncodeToString(d[:])
	pubs := make([]ed25519.PublicKey, 0, len(records))
	previous := ""
	for i, rec := range records {
		if rec.Version != 1 || rec.Index != i+1 || rec.Algorithm != "ed25519" {
			return nil, fmt.Errorf("invalid signature chain record %d", i+1)
		}
		if rec.ManifestSHA256 != manifestDigest || rec.PreviousRecordSHA256 != previous {
			return nil, fmt.Errorf("signature chain link %d is broken", i+1)
		}
		if rec.SignerName == "" || rec.SignerEmail == "" {
			return nil, fmt.Errorf("signature %d has no signer identity", i+1)
		}
		if _, err := decodeNonce(rec.Salt); err != nil {
			return nil, fmt.Errorf("signature %d has invalid salt", i+1)
		}
		raw, err := hex.DecodeString(rec.PublicKey)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid public key in signature %d", i+1)
		}
		pub := ed25519.PublicKey(raw)
		sig, err := hex.DecodeString(rec.Signature)
		if err != nil || !ed25519.Verify(pub, chainPreimage(rec), sig) {
			return nil, fmt.Errorf("signature %d verification failed", i+1)
		}
		pubs = append(pubs, pub)
		previous = recordDigest(rec)
	}
	return pubs, nil
}
func publicFingerprint(pub ed25519.PublicKey) string {
	d := sha256.Sum256(pub)
	return hex.EncodeToString(d[:])
}
func loadPinnedPublicKey(value string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(value)
	if err == nil {
		return parsePublicPEM(b)
	}
	if strings.Contains(value, "BEGIN PUBLIC KEY") {
		return parsePublicPEM([]byte(value))
	}
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("trusted key must be a PEM file or 32-byte hex key")
	}
	return ed25519.PublicKey(raw), nil
}
