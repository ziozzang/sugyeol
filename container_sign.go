package main

import (
	"bytes"
	"context"
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
	Format  string             `json:"format"`
	Version int                `json:"version"`
	Image   remoteImageSubject `json:"image"`
	Records []signatureRecord  `json:"records"`
}

func imageCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: sugyeol image <sign|verify|countersign> ...")
	}
	switch args[0] {
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
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: sugyeol image sign [-out image.meta] <image:tag>")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	subject, err := resolveRemoteImage(ctx, nil, fs.Arg(0))
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
		*out = defaultImageMetaName(subject)
	}
	if _, err := os.Stat(*out); err == nil {
		return fmt.Errorf("metadata already exists; countersign it instead: %s", *out)
	}
	bundle := containerSignatureBundle{Format: containerSignatureFormat, Version: 1, Image: subject, Records: []signatureRecord{rec}}
	if err := writeContainerSignatureBundle(*out, bundle); err != nil {
		return err
	}
	fmt.Printf("container image signed: %s\ndigest: %s\nmetadata: %s\n", subject.Reference, subject.Digest, *out)
	return nil
}

func imageVerifyCommand(args []string) error {
	fs := flag.NewFlagSet("image verify", flag.ContinueOnError)
	image := fs.String("image", "", "override image reference")
	var pubkeys stringList
	fs.Var(&pubkeys, "pubkey", "trusted public key (repeatable)")
	minimum := fs.Int("min-signatures", 1, "minimum valid signatures")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: sugyeol image verify [flags] <image.meta>")
	}
	bundle, canonical, err := loadContainerSignatureBundle(fs.Arg(0))
	if err != nil {
		return err
	}
	ref := *image
	if ref == "" {
		ref = bundle.Image.Reference
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	actual, err := resolveRemoteImage(ctx, nil, ref)
	if err != nil {
		return err
	}
	if !sameRemoteImage(bundle.Image, actual) {
		return fmt.Errorf("container image manifest changed: signed %s, current %s", bundle.Image.Digest, actual.Digest)
	}
	pubs, err := verifySignatureChain(canonical, bundle.Records)
	if err != nil {
		return err
	}
	if err := checkSignaturePolicy(pubs, pubkeys, *minimum); err != nil {
		return err
	}
	printImageSignatures(bundle, pubs)
	if len(pubkeys) == 0 {
		fmt.Fprintln(os.Stderr, tr("unpinned_warning"))
	}
	return nil
}

func imageCountersignCommand(args []string) error {
	fs := flag.NewFlagSet("image countersign", flag.ContinueOnError)
	image := fs.String("image", "", "override image reference")
	label := fs.String("label", "", "optional signed role/purpose label")
	var pubkeys stringList
	fs.Var(&pubkeys, "pubkey", "trusted existing signer key (repeatable; at least one required)")
	minimum := fs.Int("min-signatures", 1, "minimum existing signatures")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: sugyeol image countersign -pubkey trusted.pem <image.meta>")
	}
	path := fs.Arg(0)
	bundle, canonical, err := loadContainerSignatureBundle(path)
	if err != nil {
		return err
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
	ref := *image
	if ref == "" {
		ref = bundle.Image.Reference
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	actual, err := resolveRemoteImage(ctx, nil, ref)
	if err != nil {
		return err
	}
	if !sameRemoteImage(bundle.Image, actual) {
		return fmt.Errorf("container image manifest changed")
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
	if err := writeContainerSignatureBundle(path, bundle); err != nil {
		return err
	}
	fmt.Printf("container countersignature %d added: %s\n", len(bundle.Records), path)
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
	if bundle.Format != containerSignatureFormat || bundle.Version != 1 || bundle.Image.Format != "sugyeol-container-image" {
		return bundle, nil, fmt.Errorf("unsupported container signature format")
	}
	canonical, err := json.MarshalIndent(bundle.Image, "", "  ")
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

func sameRemoteImage(signed, actual remoteImageSubject) bool {
	return signed.Registry == actual.Registry && signed.Repository == actual.Repository && signed.Digest == actual.Digest && signed.MediaType == actual.MediaType && signed.ManifestSize == actual.ManifestSize && signed.ManifestSHA256 == actual.ManifestSHA256
}
func defaultImageMetaName(subject remoteImageSubject) string {
	base := filepath.Base(subject.Repository)
	short := strings.TrimPrefix(subject.Digest, "sha256:")
	if len(short) > 12 {
		short = short[:12]
	}
	return base + "-" + short + ".image.meta"
}
func printImageSignatures(bundle containerSignatureBundle, pubs []ed25519.PublicKey) {
	fmt.Printf("container image signature OK: %s\ndigest: %s\n", bundle.Image.ResolvedReference, bundle.Image.Digest)
	for i, rec := range bundle.Records {
		who := rec.SignerName + " <" + rec.SignerEmail + ">"
		if rec.SignerLabel != "" {
			who += " [" + rec.SignerLabel + "]"
		}
		fmt.Printf("signature %d/%d: %s at %s (%s)\n", i+1, len(bundle.Records), who, rec.SignedAt.Format(time.RFC3339), publicFingerprint(pubs[i]))
	}
}
