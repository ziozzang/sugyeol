package main

// The package cataloging approach in this file is adapted from the MIT-licensed
// github.com/ziozzang/bongsu-scanner project. Sugyeol adds archive validation,
// working-directory temporary storage, zstd layers, signature integration, and
// source/archive binding verification.

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
)

type sbomFile struct {
	Path, SHA256, Layer string
	Size                int64
	Data                []byte
}

type sbomPackage struct {
	Name, Version, Type, PURL, License, Source, Architecture string
}

type sbomScanResult struct {
	Name, SourceHash, SourceType, OSName, OSVersion string
	ScannedAt                                       time.Time
	Files                                           []sbomFile
	Packages                                        []sbomPackage
}

type sbomOuterEntry struct {
	Data []byte
	Temp *os.File
	Size int64
	Hash string
}

func imageSBOMCommand(args []string) error {
	if len(args) > 0 && args[0] == "verify" {
		return imageSBOMVerifyCommand(args[1:])
	}
	fs := flag.NewFlagSet("image sbom", flag.ContinueOnError)
	out := fs.String("out", "", "SPDX 2.3 JSON output path")
	sign := fs.Bool("sign", false, "sign the generated SBOM with the local identity")
	label := fs.String("label", "sbom", "signature role/purpose label")
	fs.StringVar(out, "o", "", "SPDX 2.3 JSON output path")
	fs.BoolVar(sign, "S", false, "sign the generated SBOM with the local identity")
	fs.StringVar(label, "l", "sbom", "signature role/purpose label")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: sugyeol image sbom [-S] [-o image.spdx.json] <image.tar|image.tgz>")
	}
	if *out == "" {
		*out = defaultSBOMName(fs.Arg(0))
	}
	return generateImageSBOM(fs.Arg(0), *out, *sign, *label)
}

func imageSBOMVerifyCommand(args []string) error {
	fs := flag.NewFlagSet("image sbom verify", flag.ContinueOnError)
	var pubkeys stringList
	minimum := fs.Int("min-signatures", 1, "minimum valid signatures")
	fs.Var(&pubkeys, "pubkey", "trusted public key (repeatable)")
	fs.IntVar(minimum, "n", 1, "minimum valid signatures")
	fs.Var(&pubkeys, "k", "trusted public key (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 2 || fs.NArg() > 3 {
		return fmt.Errorf("usage: sugyeol image sbom verify [-k trusted.pem] <image.tar|image.tgz> <image.spdx.json> [image.spdx.json.meta]")
	}
	archive, sbomPath := fs.Arg(0), fs.Arg(1)
	if err := verifyImageSBOMBinding(archive, sbomPath); err != nil {
		return err
	}
	fmt.Printf("SPDX SBOM source binding OK: %s -> %s\n", sbomPath, archive)
	if fs.NArg() == 3 {
		return verifyDetached(fs.Arg(2), sbomPath, pubkeys, *minimum)
	}
	if len(pubkeys) > 0 {
		return fmt.Errorf("trusted keys require a signed SBOM metadata file")
	}
	fmt.Fprintln(os.Stderr, "warning: SBOM is bound to the archive hash but has no verified signer metadata")
	return nil
}

func defaultSBOMName(archive string) string {
	base := archive
	lower := strings.ToLower(base)
	for _, suffix := range []string{".tar.gz", ".oci.tgz", ".tgz", ".oci.tar", ".tar"} {
		if strings.HasSuffix(lower, suffix) {
			base = base[:len(base)-len(suffix)]
			break
		}
	}
	return base + ".spdx.json"
}

func generateImageSBOM(archive, output string, sign bool, label string) (resultErr error) {
	if _, err := os.Lstat(output); err == nil {
		return fmt.Errorf("output already exists: %s", output)
	} else if !os.IsNotExist(err) {
		return err
	}
	subject, err := inspectContainerArchive(archive)
	if err != nil {
		return err
	}
	progress := newProgress(tr("progress_sbom"), 0)
	defer func() { progress.Finish(resultErr) }()
	result, err := scanImageArchive(commandContext, archive, subject.ArchiveSHA256)
	if err != nil {
		return err
	}
	b, err := marshalSPDX(result)
	if err != nil {
		return err
	}
	if err := writeNewFileAtomic(output, append(b, '\n')); err != nil {
		return err
	}
	progress.Finish(nil)
	fmt.Printf("SPDX 2.3 SBOM created: %s\npackages: %d\nfiles: %d\nsource sha256: %s\n", output, len(result.Packages), len(result.Files), result.SourceHash)
	if sign {
		return signCommand([]string{"-o", output + ".meta", "-l", label, output})
	}
	return nil
}

func writeNewFileAtomic(output string, data []byte) error {
	dir := filepath.Dir(output)
	if err := os.MkdirAll(dir, 0755); err != nil && dir != "." {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".sugyeol-sbom-*")
	if err != nil {
		return err
	}
	name, ok := tmp.Name(), false
	defer func() {
		tmp.Close()
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if _, err = tmp.Write(data); err == nil {
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
	if err = os.Link(name, output); err != nil {
		return err
	}
	if err = os.Remove(name); err != nil {
		return err
	}
	ok = true
	return nil
}

func scanImageArchive(ctx context.Context, archive, sourceHash string) (sbomScanResult, error) {
	entries, cleanup, err := readSBOMOuter(ctx, archive)
	if err != nil {
		return sbomScanResult{}, err
	}
	defer cleanup()
	files, kind, err := unpackSBOMImage(ctx, entries)
	if err != nil {
		return sbomScanResult{}, err
	}
	list := make([]sbomFile, 0, len(files))
	for _, f := range files {
		list = append(list, f)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Path < list[j].Path })
	packages, osName, osVersion := catalogSBOMPackages(list)
	for _, p := range packages {
		uiVerbosef("SBOM package %s %s (%s)", p.Name, p.Version, p.Type)
	}
	return sbomScanResult{Name: filepath.Base(archive), SourceHash: sourceHash, SourceType: kind,
		ScannedAt: time.Now().UTC(), Files: list, Packages: packages, OSName: osName, OSVersion: osVersion}, nil
}

func readSBOMOuter(ctx context.Context, archive string) (map[string]sbomOuterEntry, func(), error) {
	f, err := os.Open(archive)
	if err != nil {
		return nil, func() {}, err
	}
	defer f.Close()
	br := bufio.NewReader(f)
	var rd io.Reader = br
	var gz *gzip.Reader
	if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err = gzip.NewReader(br)
		if err != nil {
			return nil, func() {}, err
		}
		defer gz.Close()
		rd = gz
	}
	entries := make(map[string]sbomOuterEntry)
	var temps []*os.File
	cleanup := func() {
		for _, tmp := range temps {
			cleanupWorkingTemp(tmp)
		}
	}
	tr := tar.NewReader(rd)
	for {
		if err := ctx.Err(); err != nil {
			cleanup()
			return nil, func() {}, err
		}
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			cleanup()
			return nil, func() {}, err
		}
		if !h.FileInfo().Mode().IsRegular() {
			continue
		}
		name, err := safeSBOMPath(h.Name)
		if err != nil {
			cleanup()
			return nil, func() {}, err
		}
		if _, exists := entries[name]; exists {
			cleanup()
			return nil, func() {}, fmt.Errorf("duplicate container archive entry %q", name)
		}
		hash := sha256.New()
		e := sbomOuterEntry{Size: h.Size}
		if h.Size > maxContainerMetadata {
			tmp, err := createWorkingTemp("sbom-layer-*")
			if err != nil {
				cleanup()
				return nil, func() {}, err
			}
			temps = append(temps, tmp)
			if n, err := io.CopyN(io.MultiWriter(tmp, hash), tr, h.Size); err != nil || n != h.Size {
				cleanup()
				return nil, func() {}, fmt.Errorf("read archive entry %s: %w", name, err)
			}
			if err := tmp.Sync(); err != nil {
				cleanup()
				return nil, func() {}, err
			}
			e.Temp = tmp
		} else {
			e.Data, err = io.ReadAll(io.TeeReader(tr, hash))
			if err != nil {
				cleanup()
				return nil, func() {}, err
			}
		}
		e.Hash = hex.EncodeToString(hash.Sum(nil))
		entries[name] = e
	}
	return entries, cleanup, nil
}

func safeSBOMPath(name string) (string, error) {
	name = strings.TrimPrefix(path.Clean(strings.ReplaceAll(name, "\\", "/")), "./")
	if name == "" || name == "." || name == ".." || strings.HasPrefix(name, "/") || strings.HasPrefix(name, "../") {
		return "", fmt.Errorf("unsafe container archive path %q", name)
	}
	return name, nil
}

func unpackSBOMImage(ctx context.Context, entries map[string]sbomOuterEntry) (map[string]sbomFile, string, error) {
	manifestEntry, docker := entries["manifest.json"]
	if docker {
		var manifests []dockerArchiveManifestItem
		if err := json.Unmarshal(manifestEntry.Data, &manifests); err != nil || len(manifests) == 0 {
			return nil, "", fmt.Errorf("invalid Docker manifest.json")
		}
		if len(manifests) != 1 {
			return nil, "", fmt.Errorf("SBOM generation requires a single-platform archive; pull with --platform instead of --all-platforms")
		}
		files := make(map[string]sbomFile)
		for _, layer := range manifests[0].Layers {
			if err := ctx.Err(); err != nil {
				return nil, "", err
			}
			layerPath, err := safeSBOMPath(layer)
			if err != nil {
				return nil, "", err
			}
			e, ok := entries[layerPath]
			if !ok {
				return nil, "", fmt.Errorf("Docker layer %q missing", layer)
			}
			uiVerbosef("SBOM apply layer %s (%s)", layer, humanSize(e.Size))
			if err := applySBOMLayer(e, files, layer); err != nil {
				return nil, "", err
			}
		}
		return files, "docker-archive", nil
	}
	idx, ok := entries["index.json"]
	if !ok {
		return nil, "", fmt.Errorf("SBOM requires an OCI or Docker image archive")
	}
	var index ociIndex
	if err := json.Unmarshal(idx.Data, &index); err != nil || len(index.Manifests) != 1 {
		return nil, "", fmt.Errorf("SBOM generation requires a valid single-platform OCI index")
	}
	manifestEntry, ok = entries[containerBlobPath(index.Manifests[0].Digest)]
	if !ok {
		return nil, "", fmt.Errorf("OCI manifest blob missing")
	}
	var manifest ociManifest
	if err := json.Unmarshal(manifestEntry.Data, &manifest); err != nil {
		return nil, "", err
	}
	files := make(map[string]sbomFile)
	for _, layer := range manifest.Layers {
		e, ok := entries[containerBlobPath(layer.Digest)]
		if !ok {
			return nil, "", fmt.Errorf("OCI layer %s missing", layer.Digest)
		}
		if err := applySBOMLayer(e, files, layer.Digest); err != nil {
			return nil, "", err
		}
	}
	return files, "oci-archive", nil
}

func applySBOMLayer(entry sbomOuterEntry, files map[string]sbomFile, layer string) error {
	var input io.Reader
	if entry.Temp != nil {
		if _, err := entry.Temp.Seek(0, io.SeekStart); err != nil {
			return err
		}
		input = entry.Temp
	} else {
		input = bytes.NewReader(entry.Data)
	}
	br := bufio.NewReader(input)
	var rd io.Reader = br
	magic, _ := br.Peek(4)
	if len(magic) >= 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return err
		}
		defer gz.Close()
		rd = gz
	} else if len(magic) == 4 && bytes.Equal(magic, []byte{0x28, 0xb5, 0x2f, 0xfd}) {
		dec, err := zstd.NewReader(br, zstd.WithDecoderConcurrency(1))
		if err != nil {
			return err
		}
		defer dec.Close()
		rd = dec
	}
	tr := tar.NewReader(rd)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read layer %s: %w", layer, err)
		}
		name, err := safeSBOMPath(h.Name)
		if err != nil {
			return err
		}
		base := path.Base(name)
		if strings.HasPrefix(base, ".wh.") {
			dir := path.Dir(name)
			if base == ".wh..wh..opq" {
				prefix := strings.TrimPrefix(dir+"/", "./")
				for p := range files {
					if strings.HasPrefix(p, prefix) {
						delete(files, p)
					}
				}
			} else {
				victim := path.Join(dir, strings.TrimPrefix(base, ".wh."))
				delete(files, victim)
				for p := range files {
					if strings.HasPrefix(p, victim+"/") {
						delete(files, p)
					}
				}
			}
			continue
		}
		if !h.FileInfo().Mode().IsRegular() {
			continue
		}
		hash := sha256.New()
		var data []byte
		if h.Size <= maxContainerMetadata && sbomInteresting(name) {
			data, err = io.ReadAll(io.TeeReader(tr, hash))
		} else {
			_, err = io.Copy(hash, tr)
		}
		if err != nil {
			return err
		}
		files[name] = sbomFile{Path: name, Size: h.Size, SHA256: hex.EncodeToString(hash.Sum(nil)), Data: data, Layer: layer}
	}
}

func sbomInteresting(p string) bool {
	p = strings.ToLower(p)
	base := path.Base(p)
	if p == "var/lib/dpkg/status" || p == "lib/apk/db/installed" || strings.HasSuffix(p, "/os-release") {
		return true
	}
	switch base {
	case "package-lock.json", "npm-shrinkwrap.json", "go.mod", "requirements.txt", "cargo.lock", "pom.properties":
		return true
	}
	return strings.HasSuffix(p, ".dist-info/metadata")
}

func catalogSBOMPackages(files []sbomFile) ([]sbomPackage, string, string) {
	seen := make(map[string]sbomPackage)
	add := func(p sbomPackage) {
		if p.Name == "" {
			return
		}
		if p.PURL == "" {
			p.PURL = makeSBOMPURL(p.Type, p.Name, p.Version)
		}
		seen[p.Type+"\x00"+p.Name+"\x00"+p.Version] = p
	}
	osName, osVersion := "", ""
	for _, f := range files {
		if len(f.Data) == 0 {
			continue
		}
		lower := strings.ToLower(f.Path)
		switch {
		case lower == "var/lib/dpkg/status":
			for _, p := range sbomParagraphs(f.Data) {
				if strings.HasPrefix(p["Status"], "install ok installed") {
					add(sbomPackage{Name: p["Package"], Version: p["Version"], Architecture: p["Architecture"], Type: "deb", Source: f.Path})
				}
			}
		case lower == "lib/apk/db/installed":
			for _, p := range sbomAPKParagraphs(f.Data) {
				add(sbomPackage{Name: p["P"], Version: p["V"], Architecture: p["A"], License: p["L"], Type: "apk", Source: f.Path})
			}
		case lower == "etc/os-release" || strings.HasSuffix(lower, "/os-release"):
			v := sbomKeyValues(f.Data, "=")
			osName, osVersion = sbomTrim(v["ID"]), sbomTrim(v["VERSION_ID"])
		case path.Base(lower) == "package-lock.json" || path.Base(lower) == "npm-shrinkwrap.json":
			var lock struct {
				Packages map[string]struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				} `json:"packages"`
				Dependencies map[string]struct {
					Version string `json:"version"`
				} `json:"dependencies"`
			}
			if json.Unmarshal(f.Data, &lock) == nil {
				for loc, p := range lock.Packages {
					name := p.Name
					if name == "" && strings.Contains(loc, "node_modules/") {
						name = loc[strings.LastIndex(loc, "node_modules/")+len("node_modules/"):]
					}
					if loc != "" {
						add(sbomPackage{Name: name, Version: p.Version, Type: "npm", Source: f.Path})
					}
				}
				if len(lock.Packages) == 0 {
					for name, p := range lock.Dependencies {
						add(sbomPackage{Name: name, Version: p.Version, Type: "npm", Source: f.Path})
					}
				}
			}
		case path.Base(lower) == "go.mod":
			scanSBOMGoMod(string(f.Data), f.Path, add)
		case path.Base(lower) == "requirements.txt":
			scanSBOMRequirements(string(f.Data), f.Path, add)
		case strings.HasSuffix(lower, ".dist-info/metadata"):
			if p := sbomParagraphs(f.Data); len(p) > 0 {
				add(sbomPackage{Name: p[0]["Name"], Version: p[0]["Version"], License: p[0]["License"], Type: "pypi", Source: f.Path})
			}
		case path.Base(lower) == "cargo.lock":
			for _, p := range sbomTOMLPackages(string(f.Data)) {
				add(sbomPackage{Name: p["name"], Version: p["version"], Type: "cargo", Source: f.Path})
			}
		case path.Base(lower) == "pom.properties":
			v := sbomKeyValues(f.Data, "=")
			p := sbomPackage{Name: v["artifactId"], Version: v["version"], Type: "maven", Source: f.Path}
			if v["groupId"] != "" {
				p.PURL = "pkg:maven/" + url.PathEscape(v["groupId"]) + "/" + url.PathEscape(p.Name) + "@" + url.PathEscape(p.Version)
			}
			add(p)
		}
	}
	out := make([]sbomPackage, 0, len(seen))
	for _, p := range seen {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name == out[j].Name {
			return out[i].Version < out[j].Version
		}
		return out[i].Name < out[j].Name
	})
	return out, osName, osVersion
}

func sbomParagraphs(b []byte) []map[string]string {
	var out []map[string]string
	cur, last := map[string]string{}, ""
	s := bufio.NewScanner(strings.NewReader(strings.ReplaceAll(string(b), "\r\n", "\n")))
	for s.Scan() {
		line := s.Text()
		if line == "" {
			if len(cur) > 0 {
				out, cur = append(out, cur), map[string]string{}
			}
			last = ""
			continue
		}
		if (line[0] == ' ' || line[0] == '\t') && last != "" {
			cur[last] += "\n" + strings.TrimSpace(line)
		} else if i := strings.IndexByte(line, ':'); i > 0 {
			last, cur[line[:i]] = line[:i], strings.TrimSpace(line[i+1:])
		}
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

func sbomAPKParagraphs(b []byte) []map[string]string {
	var out []map[string]string
	cur := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		if line == "" {
			if len(cur) > 0 {
				out, cur = append(out, cur), map[string]string{}
			}
		} else if len(line) > 2 && line[1] == ':' {
			cur[line[:1]] = line[2:]
		}
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

func scanSBOMGoMod(s, source string, add func(sbomPackage)) {
	inBlock := false
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "//", 2)[0])
		if line == "require (" {
			inBlock = true
			continue
		}
		if inBlock && line == ")" {
			inBlock = false
			continue
		}
		if strings.HasPrefix(line, "require ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "require "))
		} else if !inBlock {
			continue
		}
		if fields := strings.Fields(line); len(fields) >= 2 {
			add(sbomPackage{Name: fields[0], Version: fields[1], Type: "golang", Source: source})
		}
	}
}

func scanSBOMRequirements(s, source string, add func(sbomPackage)) {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" || strings.HasPrefix(line, "-") {
			continue
		}
		for _, sep := range []string{"==", "~=", ">=", "<=", "!="} {
			if i := strings.Index(line, sep); i > 0 {
				add(sbomPackage{Name: strings.TrimSpace(line[:i]), Version: strings.TrimSpace(strings.SplitN(line[i+len(sep):], ";", 2)[0]), Type: "pypi", Source: source})
				break
			}
		}
	}
}

func sbomTOMLPackages(s string) []map[string]string {
	var out []map[string]string
	var cur map[string]string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "[[package]]" {
			if cur != nil {
				out = append(out, cur)
			}
			cur = map[string]string{}
		} else if cur != nil {
			if i := strings.IndexByte(line, '='); i > 0 {
				cur[strings.TrimSpace(line[:i])] = sbomTrim(strings.TrimSpace(line[i+1:]))
			}
		}
	}
	if cur != nil {
		out = append(out, cur)
	}
	return out
}

func sbomKeyValues(b []byte, sep string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		if i := strings.Index(line, sep); i > 0 {
			out[strings.TrimSpace(line[:i])] = strings.TrimSpace(line[i+len(sep):])
		}
	}
	return out
}

func sbomTrim(s string) string { return strings.Trim(s, `"'`) }
func makeSBOMPURL(kind, name, version string) string {
	if kind == "" || name == "" {
		return ""
	}
	p := "pkg:" + kind + "/" + url.PathEscape(name)
	if version != "" {
		p += "@" + url.PathEscape(version)
	}
	return p
}

var sbomInvalidID = regexp.MustCompile(`[^A-Za-z0-9.-]+`)

type spdxChecksum struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"checksumValue"`
}
type spdxPackage struct {
	SPDXID           string            `json:"SPDXID"`
	Name             string            `json:"name"`
	VersionInfo      string            `json:"versionInfo,omitempty"`
	PackageComment   string            `json:"packageComment,omitempty"`
	DownloadLocation string            `json:"downloadLocation"`
	LicenseConcluded string            `json:"licenseConcluded"`
	LicenseDeclared  string            `json:"licenseDeclared"`
	CopyrightText    string            `json:"copyrightText"`
	FilesAnalyzed    bool              `json:"filesAnalyzed"`
	Checksums        []spdxChecksum    `json:"checksums,omitempty"`
	ExternalRefs     []spdxExternalRef `json:"externalRefs,omitempty"`
}
type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}
type spdxFile struct {
	SPDXID           string         `json:"SPDXID"`
	FileName         string         `json:"fileName"`
	LicenseConcluded string         `json:"licenseConcluded"`
	CopyrightText    string         `json:"copyrightText"`
	Checksums        []spdxChecksum `json:"checksums"`
}
type spdxRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}
type spdxDocument struct {
	SPDXVersion       string             `json:"spdxVersion"`
	DataLicense       string             `json:"dataLicense"`
	SPDXID            string             `json:"SPDXID"`
	Name              string             `json:"name"`
	DocumentNamespace string             `json:"documentNamespace"`
	CreationInfo      any                `json:"creationInfo"`
	Packages          []spdxPackage      `json:"packages"`
	Files             []spdxFile         `json:"files,omitempty"`
	Relationships     []spdxRelationship `json:"relationships"`
}

func marshalSPDX(r sbomScanResult) ([]byte, error) {
	namespaceHash := sha256.Sum256([]byte(r.Name + "\x00" + r.SourceHash + "\x00" + r.ScannedAt.Format(time.RFC3339Nano)))
	doc := spdxDocument{SPDXVersion: "SPDX-2.3", DataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT", Name: r.Name,
		DocumentNamespace: "https://github.com/ziozzang/sugyeol/spdx/" + hex.EncodeToString(namespaceHash[:]),
		CreationInfo:      map[string]any{"created": r.ScannedAt.Format(time.RFC3339), "creators": []string{"Tool: sugyeol-" + version}},
		Relationships:     []spdxRelationship{{SPDXElementID: "SPDXRef-DOCUMENT", RelationshipType: "DESCRIBES", RelatedSPDXElement: "SPDXRef-Image"}}}
	root := spdxPackage{SPDXID: "SPDXRef-Image", Name: r.Name, DownloadLocation: "NOASSERTION", FilesAnalyzed: false,
		LicenseConcluded: "NOASSERTION", LicenseDeclared: "NOASSERTION", CopyrightText: "NOASSERTION",
		Checksums:      []spdxChecksum{{Algorithm: "SHA256", Value: r.SourceHash}},
		PackageComment: fmt.Sprintf("Sugyeol scanned %s image; operating system: %s %s", r.SourceType, r.OSName, r.OSVersion)}
	doc.Packages = append(doc.Packages, root)
	for i, p := range r.Packages {
		id := fmt.Sprintf("SPDXRef-Package-%d-%s", i, safeSBOMID(p.Name))
		license := p.License
		if license == "" {
			license = "NOASSERTION"
		}
		pkg := spdxPackage{SPDXID: id, Name: p.Name, VersionInfo: p.Version, DownloadLocation: "NOASSERTION", FilesAnalyzed: false,
			LicenseConcluded: "NOASSERTION", LicenseDeclared: license, CopyrightText: "NOASSERTION", PackageComment: "Sugyeol detected package metadata at " + p.Source}
		if p.PURL != "" {
			pkg.ExternalRefs = []spdxExternalRef{{ReferenceCategory: "PACKAGE-MANAGER", ReferenceType: "purl", ReferenceLocator: p.PURL}}
		}
		doc.Packages = append(doc.Packages, pkg)
		doc.Relationships = append(doc.Relationships, spdxRelationship{SPDXElementID: "SPDXRef-Image", RelationshipType: "CONTAINS", RelatedSPDXElement: id})
	}
	for i, f := range r.Files {
		id := fmt.Sprintf("SPDXRef-File-%d", i)
		doc.Files = append(doc.Files, spdxFile{SPDXID: id, FileName: "./" + f.Path,
			Checksums: []spdxChecksum{{Algorithm: "SHA256", Value: f.SHA256}}, LicenseConcluded: "NOASSERTION", CopyrightText: "NOASSERTION"})
		doc.Relationships = append(doc.Relationships, spdxRelationship{SPDXElementID: "SPDXRef-Image", RelationshipType: "CONTAINS", RelatedSPDXElement: id})
	}
	return json.MarshalIndent(doc, "", "  ")
}

func safeSBOMID(s string) string {
	s = sbomInvalidID.ReplaceAllString(s, "-")
	if s == "" {
		return "unknown"
	}
	return s
}

func verifyImageSBOMBinding(archive, sbomPath string) error {
	subject, err := inspectContainerArchive(archive)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(sbomPath)
	if err != nil {
		return err
	}
	var doc spdxDocument
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&doc); err != nil {
		return fmt.Errorf("invalid SPDX JSON: %w", err)
	}
	if dec.Decode(&struct{}{}) != io.EOF || doc.SPDXVersion != "SPDX-2.3" || doc.DataLicense != "CC0-1.0" {
		return fmt.Errorf("invalid or unsupported SPDX document")
	}
	for _, p := range doc.Packages {
		if p.SPDXID != "SPDXRef-Image" {
			continue
		}
		for _, sum := range p.Checksums {
			if strings.EqualFold(sum.Algorithm, "SHA256") {
				if sum.Value != subject.ArchiveSHA256 {
					return fmt.Errorf("SBOM source SHA-256 mismatch: %s != %s", sum.Value, subject.ArchiveSHA256)
				}
				return nil
			}
		}
	}
	return fmt.Errorf("SPDX document has no Sugyeol image source SHA-256")
}
