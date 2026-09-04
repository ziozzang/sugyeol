package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const containerSignatureFormat = "sugyeol-container-signature"

type containerSignatureBundle struct {
	Format  string              `json:"format"`
	Version int                 `json:"version"`
	Archive *localImageSubject  `json:"archive,omitempty"`
	Image   *remoteImageSubject `json:"image,omitempty"`
	Records []signatureRecord   `json:"records"`
}

func imageCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: sugyeol image <pull|sbom|sign|verify|countersign> ...")
	}
	switch args[0] {
	case "pull", "download", "export":
		return imagePullCommand(args[1:])
	case "sbom":
		return imageSBOMCommand(args[1:])
	case "sign":
		return imageSignCommand(args[1:])
	case "verify":
		return imageVerifyCommand(args[1:])
	case "countersign", "endorse", "cosign":
		return imageCountersignCommand(args[1:])
	default:
		return fmt.Errorf("unknown image command %q", args[0])
	}
}

func imageSignCommand(args []string) error {
	fs := flag.NewFlagSet("image sign", flag.ContinueOnError)
	out := fs.String("out", "", "output metadata path")
	label := fs.String("label", "", "optional signed role/purpose label")
	fs.StringVar(out, "o", "", "output metadata path")
	fs.StringVar(label, "l", "", "optional signed role/purpose label")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: sugyeol image sign [-out image.meta] <image.tar|image.tgz>")
	}
	archivePath := fs.Arg(0)
	subject, err := inspectContainerArchive(archivePath)
	if err != nil {
		return err
	}
	manifestBytes, err := json.MarshalIndent(subject, "", "  ")
	if err != nil {
		return err
	}
	priv, _, identity, err := loadSigningIdentity()
	if err != nil {
		return err
	}
	rec, err := makeChainRecord(manifestBytes, nil, 1, identity, *label, priv, time.Now().UTC())
	if err != nil {
		return err
	}
	if *out == "" {
		*out = defaultLocalImageMetaName(archivePath)
	}
	if _, err := os.Stat(*out); err == nil {
		return fmt.Errorf("metadata already exists; countersign it instead: %s", *out)
	}
	bundle := containerSignatureBundle{Format: containerSignatureFormat, Version: 2, Archive: &subject, Records: []signatureRecord{rec}}
	if err := writeContainerSignatureBundle(*out, bundle); err != nil {
		return err
	}
	fmt.Printf("container archive signed: %s\narchive sha256: %s\nmetadata: %s\n", archivePath, subject.ArchiveSHA256, *out)
	pub := priv.Public().(ed25519.PublicKey)
	printSignatureRecordDetails(os.Stdout, []signatureRecord{rec}, []ed25519.PublicKey{pub}, rec.Index, nil, false)
	return nil
}

func imageVerifyCommand(args []string) error {
	fs := flag.NewFlagSet("image verify", flag.ContinueOnError)
	var pubkeys stringList
	fs.Var(&pubkeys, "pubkey", "trusted public key (repeatable)")
	minimum := fs.Int("min-signatures", 1, "minimum valid signatures")
	fs.Var(&pubkeys, "k", "trusted public key (repeatable)")
	fs.IntVar(minimum, "n", 1, "minimum valid signatures")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 || fs.NArg() > 2 {
		return fmt.Errorf("usage: sugyeol image verify [flags] <image.tar|image.tgz> [image.meta]")
	}
	archivePath := fs.Arg(0)
	metaPath := defaultLocalImageMetaName(archivePath)
	if fs.NArg() == 2 {
		metaPath = fs.Arg(1)
	}
	bundle, canonical, err := loadContainerSignatureBundle(metaPath)
	if err != nil {
		return err
	}
	if bundle.Archive == nil {
		return fmt.Errorf("metadata signs a remote reference, not a local container archive")
	}
	actual, err := inspectContainerArchive(archivePath)
	if err != nil {
		return err
	}
	if !sameLocalImage(*bundle.Archive, actual) {
		return fmt.Errorf("container archive or manifest graph changed: signed %s, current %s", bundle.Archive.ArchiveSHA256, actual.ArchiveSHA256)
	}
	pubs, err := verifySignatureChain(canonical, bundle.Records)
	if err != nil {
		return err
	}
	trusted, err := checkSignaturePolicyWithTrust(pubs, pubkeys, *minimum)
	if err != nil {
		return err
	}
	printLocalImageSignatures(bundle, pubs, trusted, len(pubkeys) > 0, archivePath)
	if len(pubkeys) == 0 {
		fmt.Fprintln(os.Stderr, tr("unpinned_warning"))
	}
	return nil
}

func imageCountersignCommand(args []string) error {
	fs := flag.NewFlagSet("image countersign", flag.ContinueOnError)
	out := fs.String("out", "", "output metadata (default: replace metadata atomically)")
	label := fs.String("label", "", "optional signed role/purpose label")
	var pubkeys stringList
	fs.Var(&pubkeys, "pubkey", "trusted existing signer key (repeatable; at least one required)")
	minimum := fs.Int("min-signatures", 1, "minimum existing signatures")
	fs.StringVar(out, "o", "", "output metadata (default: replace metadata atomically)")
	fs.StringVar(label, "l", "", "optional signed role/purpose label")
	fs.Var(&pubkeys, "k", "trusted existing signer key (repeatable; at least one required)")
	fs.IntVar(minimum, "n", 1, "minimum existing signatures")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 || fs.NArg() > 2 {
		return fmt.Errorf("usage: sugyeol image countersign -pubkey trusted.pem <image.tar|image.tgz> [image.meta]")
	}
	archivePath := fs.Arg(0)
	metaPath := defaultLocalImageMetaName(archivePath)
	if fs.NArg() == 2 {
		metaPath = fs.Arg(1)
	}
	bundle, canonical, err := loadContainerSignatureBundle(metaPath)
	if err != nil {
		return err
	}
	if bundle.Archive == nil {
		return fmt.Errorf("metadata signs a remote reference, not a local container archive")
	}
	pubs, err := verifySignatureChain(canonical, bundle.Records)
	if err != nil {
		return err
	}
	if len(pubkeys) == 0 {
		return fmt.Errorf("countersigning requires at least one trusted existing signer via -pubkey")
	}
	if err := checkSignaturePolicy(pubs, pubkeys, *minimum); err != nil {
		return err
	}
	actual, err := inspectContainerArchive(archivePath)
	if err != nil {
		return err
	}
	if !sameLocalImage(*bundle.Archive, actual) {
		return fmt.Errorf("container archive or manifest graph changed")
	}
	priv, _, identity, err := loadSigningIdentity()
	if err != nil {
		return err
	}
	previous := &bundle.Records[len(bundle.Records)-1]
	rec, err := makeChainRecord(canonical, previous, len(bundle.Records)+1, identity, *label, priv, time.Now().UTC())
	if err != nil {
		return err
	}
	bundle.Records = append(bundle.Records, rec)
	destination := metaPath
	if *out != "" {
		destination = *out
	}
	if err := writeContainerSignatureBundle(destination, bundle); err != nil {
		return err
	}
	fmt.Printf("container countersignature %d added: %s\n", len(bundle.Records), destination)
	pub := priv.Public().(ed25519.PublicKey)
	printSignatureRecordDetails(os.Stdout, []signatureRecord{rec}, []ed25519.PublicKey{pub}, rec.Index, nil, false)
	return nil
}

func loadContainerSignatureBundle(path string) (containerSignatureBundle, []byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return containerSignatureBundle{}, nil, err
	}
	var bundle containerSignatureBundle
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&bundle); err != nil {
		return bundle, nil, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return bundle, nil, fmt.Errorf("trailing data in container metadata")
	}
	if bundle.Format != containerSignatureFormat || (bundle.Version != 1 && bundle.Version != 2) {
		return bundle, nil, fmt.Errorf("unsupported container signature format")
	}
	var subject any
	if bundle.Version == 1 && bundle.Image != nil && bundle.Image.Format == "sugyeol-container-image" {
		subject = bundle.Image
	} else if bundle.Version == 2 && bundle.Archive != nil && bundle.Archive.Format == containerArchiveFormat {
		subject = bundle.Archive
	} else {
		return bundle, nil, fmt.Errorf("container signature subject does not match its version")
	}
	canonical, err := json.MarshalIndent(subject, "", "  ")
	return bundle, canonical, err
}

func writeContainerSignatureBundle(path string, bundle containerSignatureBundle) error {
	b, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".sugyeol-image-meta-*")
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

func sameLocalImage(signed, actual localImageSubject) bool {
	actual.ArchiveFile = signed.ArchiveFile
	signedBytes, err1 := json.Marshal(signed)
	actualBytes, err2 := json.Marshal(actual)
	return err1 == nil && err2 == nil && bytes.Equal(signedBytes, actualBytes)
}

func defaultLocalImageMetaName(archivePath string) string {
	base := archivePath
	lower := strings.ToLower(base)
	for _, suffix := range []string{".oci.tar.gz", ".oci.tgz", ".oci.tar", ".tar.gz", ".tgz", ".tar"} {
		if strings.HasSuffix(lower, suffix) {
			base = base[:len(base)-len(suffix)]
			break
		}
	}
	return base + ".image.meta"
}

func printLocalImageSignatures(bundle containerSignatureBundle, pubs []ed25519.PublicKey, trusted map[string]bool, pinningConfigured bool, archivePath string) {
	fmt.Printf("container archive signature OK: %s\narchive sha256: %s\nformat: %s\n", archivePath, bundle.Archive.ArchiveSHA256, bundle.Archive.ArchiveFormat)
	fmt.Printf(tr("container_signed_subject"), len(bundle.Archive.RootDescriptors), len(bundle.Archive.References), len(bundle.Records))
	printSignatureRecordDetails(os.Stdout, bundle.Records, pubs, len(bundle.Records), trusted, pinningConfigured)
}
