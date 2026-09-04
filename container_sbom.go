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
	"runtime"
	"sort"
	"strings"
	"time"

	rpmdb "github.com/anchore/go-rpmdb/pkg"
	_ "github.com/glebarez/go-sqlite"
	"github.com/klauspost/compress/zstd"
)

type sbomFile struct {
	Path, SHA256, Layer string
	Size                int64
	Data                []byte
	Temp                *os.File
}

type sbomPackage struct {
	Name, Version, Type, PURL, License, Source, Architecture string
}

type sbomScanResult struct {
	Name, SourceHash, SourceType, ManifestDigest, OSName, OSVersion string
	ScannedAt                                                       time.Time
	Platform                                                        ociPlatform
	Files                                                           []sbomFile
	Packages                                                        []sbomPackage
	Warnings                                                        []string
}

type sbomImageTarget struct {
	Platform       ociPlatform
	ManifestDigest string
	Layers         []string
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
	platform := fs.String("platform", runtime.GOOS+"/"+runtime.GOARCH, "platform os/arch[/variant]")
	allPlatforms := fs.Bool("all-platforms", false, "generate one SBOM per platform into the output directory")
	fs.StringVar(out, "o", "", "SPDX 2.3 JSON output path")
	fs.BoolVar(sign, "S", false, "sign the generated SBOM with the local identity")
	fs.StringVar(label, "l", "sbom", "signature role/purpose label")
	fs.StringVar(platform, "p", runtime.GOOS+"/"+runtime.GOARCH, "platform os/arch[/variant]")
	fs.BoolVar(allPlatforms, "a", false, "generate one SBOM per platform into the output directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: sugyeol image sbom [-S] [-p linux/amd64|-a] [-o image.spdx.json|directory] <image.tar|image.tgz>")
	}
	if *out == "" {
		if *allPlatforms {
			*out = strings.TrimSuffix(defaultSBOMName(fs.Arg(0)), ".spdx.json") + "-sboms"
		} else {
			*out = defaultSBOMName(fs.Arg(0))
		}
	}
	return generateImageSBOMs(fs.Arg(0), *out, *sign, *label, *platform, *allPlatforms)
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
	return generateImageSBOMs(archive, output, sign, label, runtime.GOOS+"/"+runtime.GOARCH, false)
}

func generateImageSBOMs(archive, output string, sign bool, label, platform string, allPlatforms bool) (resultErr error) {
	subject, err := inspectContainerArchive(archive)
	if err != nil {
		return err
	}
	wanted, err := parseOCIPlatform(platform)
	if err != nil {
		return err
	}
	progress := newProgress(tr("progress_sbom"), 0)
	defer func() { progress.Finish(resultErr) }()
	results, err := scanImageArchivePlatforms(commandContext, archive, subject.ArchiveSHA256, wanted, allPlatforms, progress)
	if err != nil {
		return err
	}
	if allPlatforms {
		if info, statErr := os.Lstat(output); statErr == nil && !info.IsDir() {
			return fmt.Errorf("multi-platform SBOM output must be a directory: %s", output)
		} else if statErr != nil && !os.IsNotExist(statErr) {
			return statErr
		}
		if err := os.MkdirAll(output, 0755); err != nil {
			return err
		}
	} else if _, err := os.Lstat(output); err == nil {
		return fmt.Errorf("output already exists: %s", output)
	} else if !os.IsNotExist(err) {
		return err
	}
	for _, result := range results {
		destination := output
		if allPlatforms {
			destination = filepath.Join(output, sbomPlatformFilename(result.Platform))
		}
		b, err := marshalSPDX(result)
		if err != nil {
			return err
		}
		if err := writeNewFileAtomic(destination, append(b, '\n')); err != nil {
			return err
		}
		fmt.Printf("SPDX 2.3 SBOM created: %s\nplatform: %s\npackages: %d\nfiles: %d\nsource sha256: %s\n", destination, formatOCIPlatform(result.Platform), len(result.Packages), len(result.Files), result.SourceHash)
		for _, warning := range result.Warnings {
			fmt.Fprintf(os.Stderr, "warning: SBOM coverage incomplete: %s\n", warning)
		}
		if sign {
			if err := signCommand([]string{"-o", destination + ".meta", "-l", label, destination}); err != nil {
				return err
			}
		}
	}
	progress.Finish(nil)
	return nil
}

func sbomPlatformFilename(platform ociPlatform) string {
	name := platform.OS + "-" + platform.Architecture
	if platform.Variant != "" {
		name += "-" + platform.Variant
	}
	return safeSBOMID(name) + ".spdx.json"
}

func formatOCIPlatform(platform ociPlatform) string {
	value := platform.OS + "/" + platform.Architecture
	if platform.Variant != "" {
		value += "/" + platform.Variant
	}
	return strings.Trim(value, "/")
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
	results, err := scanImageArchivePlatforms(ctx, archive, sourceHash, ociPlatform{OS: runtime.GOOS, Architecture: runtime.GOARCH}, false, nil)
	if err != nil {
		return sbomScanResult{}, err
	}
	if len(results) != 1 {
		return sbomScanResult{}, fmt.Errorf("expected one SBOM result, got %d", len(results))
	}
	return results[0], nil
}

func scanImageArchivePlatforms(ctx context.Context, archive, sourceHash string, wanted ociPlatform, allPlatforms bool, progress *progressBar) ([]sbomScanResult, error) {
	entries, cleanup, err := readSBOMOuter(ctx, archive)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	targets, kind, err := resolveSBOMTargets(entries)
	if err != nil {
		return nil, err
	}
	if !allPlatforms {
		matches := targets[:0]
		for _, target := range targets {
			if platformMatches(target.Platform, wanted) {
				matches = append(matches, target)
			}
		}
		if len(matches) != 1 {
			return nil, fmt.Errorf("platform %s matched %d images; use --platform or --all-platforms", formatOCIPlatform(wanted), len(matches))
		}
		targets = matches
	}
	var total int64
	for _, target := range targets {
		for _, layer := range target.Layers {
			if entry, ok := entries[layer]; ok && entry.Size > 0 && total <= (1<<63-1)-entry.Size {
				total += entry.Size
			}
		}
	}
	progress.SetTotal(total)
	results := make([]sbomScanResult, 0, len(targets))
	for _, target := range targets {
		files := make(map[string]sbomFile)
		for _, layer := range target.Layers {
			if err := ctx.Err(); err != nil {
				cleanupSBOMTemps(files)
				return nil, err
			}
			e, ok := entries[layer]
			if !ok {
				cleanupSBOMTemps(files)
				return nil, fmt.Errorf("image layer %q missing", layer)
			}
			uiVerbosef("SBOM apply %s layer %s (%s)", formatOCIPlatform(target.Platform), layer, humanSize(e.Size))
			if err := applySBOMLayer(e, files, layer, progress); err != nil {
				cleanupSBOMTemps(files)
				return nil, err
			}
		}
		list := make([]sbomFile, 0, len(files))
		for _, file := range files {
			list = append(list, file)
		}
		sort.Slice(list, func(i, j int) bool { return list[i].Path < list[j].Path })
		packages, osName, osVersion, warnings := catalogSBOMPackages(list)
		cleanupSBOMTemps(files)
		for i := range list {
			list[i].Temp = nil
		}
		for _, p := range packages {
			uiVerbosef("SBOM package %s %s (%s)", p.Name, p.Version, p.Type)
		}
		name := filepath.Base(archive)
		if len(targets) > 1 {
			name += "@" + formatOCIPlatform(target.Platform)
		}
		results = append(results, sbomScanResult{Name: name, SourceHash: sourceHash, SourceType: kind, ManifestDigest: target.ManifestDigest, Platform: target.Platform,
			ScannedAt: time.Now().UTC(), Files: list, Packages: packages, OSName: osName, OSVersion: osVersion, Warnings: warnings})
	}
	return results, nil
}

func platformMatches(actual, wanted ociPlatform) bool {
	return actual.OS == wanted.OS && actual.Architecture == wanted.Architecture && (wanted.Variant == "" || actual.Variant == wanted.Variant)
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

func resolveSBOMTargets(entries map[string]sbomOuterEntry) ([]sbomImageTarget, string, error) {
	manifestEntry, docker := entries["manifest.json"]
	_, hasOCIIndex := entries["index.json"]
	if docker && !hasOCIIndex {
		var manifests []dockerArchiveManifestItem
		if err := json.Unmarshal(manifestEntry.Data, &manifests); err != nil || len(manifests) == 0 {
			return nil, "", fmt.Errorf("invalid Docker manifest.json")
		}
		targets := make([]sbomImageTarget, 0, len(manifests))
		for _, manifest := range manifests {
			configPath, err := safeSBOMPath(manifest.Config)
			if err != nil {
				return nil, "", err
			}
			config, ok := entries[configPath]
			if !ok {
				return nil, "", fmt.Errorf("Docker config %q missing", manifest.Config)
			}
			var imageConfig struct {
				Architecture string `json:"architecture"`
				OS           string `json:"os"`
				Variant      string `json:"variant"`
			}
			if err := json.Unmarshal(config.Data, &imageConfig); err != nil || imageConfig.OS == "" || imageConfig.Architecture == "" {
				return nil, "", fmt.Errorf("Docker config %q has no valid platform", manifest.Config)
			}
			target := sbomImageTarget{Platform: ociPlatform{OS: imageConfig.OS, Architecture: imageConfig.Architecture, Variant: imageConfig.Variant}}
			for _, layer := range manifest.Layers {
				layerPath, err := safeSBOMPath(layer)
				if err != nil {
					return nil, "", err
				}
				if _, ok := entries[layerPath]; !ok {
					return nil, "", fmt.Errorf("Docker layer %q missing", layer)
				}
				target.Layers = append(target.Layers, layerPath)
			}
			targets = append(targets, target)
		}
		return targets, "docker-archive", nil
	}
	idx, ok := entries["index.json"]
	if !ok {
		return nil, "", fmt.Errorf("SBOM requires an OCI or Docker image archive")
	}
	var index ociIndex
	if err := json.Unmarshal(idx.Data, &index); err != nil || len(index.Manifests) == 0 {
		return nil, "", fmt.Errorf("invalid OCI index")
	}
	var targets []sbomImageTarget
	visited := make(map[string]bool)
	var visit func(ociDescriptor, *ociPlatform) error
	visit = func(descriptor ociDescriptor, inherited *ociPlatform) error {
		visitKey := descriptor.Digest
		if inherited != nil {
			visitKey += "\x00" + formatOCIPlatform(*inherited)
		}
		if visited[visitKey] {
			return nil
		}
		visited[visitKey] = true
		entry, ok := entries[containerBlobPath(descriptor.Digest)]
		if !ok {
			return fmt.Errorf("OCI descriptor blob missing: %s", descriptor.Digest)
		}
		platform := descriptor.Platform
		if platform == nil {
			platform = inherited
		}
		switch descriptor.MediaType {
		case ociIndexMediaType, dockerIndexMediaType:
			var nested ociIndex
			if err := json.Unmarshal(entry.Data, &nested); err != nil {
				return err
			}
			for _, child := range nested.Manifests {
				if err := visit(child, platform); err != nil {
					return err
				}
			}
		case ociManifestMediaType, dockerManifestMediaType:
			var manifest ociManifest
			if err := json.Unmarshal(entry.Data, &manifest); err != nil {
				return err
			}
			if manifest.Config.MediaType != ociConfigMediaType && manifest.Config.MediaType != dockerConfigMediaType {
				return nil
			}
			if !hasOnlyImageLayers(manifest) {
				uiVerbosef("SBOM skip non-runnable artifact manifest %s", descriptor.Digest)
				return nil
			}
			configEntry, ok := entries[containerBlobPath(manifest.Config.Digest)]
			if !ok {
				return fmt.Errorf("OCI config blob missing: %s", manifest.Config.Digest)
			}
			var config struct {
				Architecture string `json:"architecture"`
				OS           string `json:"os"`
				Variant      string `json:"variant"`
			}
			if err := json.Unmarshal(configEntry.Data, &config); err != nil {
				return err
			}
			resolved := ociPlatform{OS: config.OS, Architecture: config.Architecture, Variant: config.Variant}
			if platform != nil {
				resolved = *platform
			}
			if resolved.OS == "" || resolved.Architecture == "" || resolved.OS == "unknown" || resolved.Architecture == "unknown" {
				return nil
			}
			target := sbomImageTarget{Platform: resolved, ManifestDigest: descriptor.Digest}
			for _, layer := range manifest.Layers {
				layerPath := containerBlobPath(layer.Digest)
				if _, ok := entries[layerPath]; !ok {
					return fmt.Errorf("OCI layer %s missing", layer.Digest)
				}
				target.Layers = append(target.Layers, layerPath)
			}
			targets = append(targets, target)
		}
		return nil
	}
	for _, descriptor := range index.Manifests {
		if err := visit(descriptor, descriptor.Platform); err != nil {
			return nil, "", err
		}
	}
	if len(targets) == 0 {
		return nil, "", fmt.Errorf("OCI archive has no runnable image manifests")
	}
	return targets, "oci-archive", nil
}

func applySBOMLayer(entry sbomOuterEntry, files map[string]sbomFile, layer string, progress *progressBar) error {
	var input io.Reader
	if entry.Temp != nil {
		if _, err := entry.Temp.Seek(0, io.SeekStart); err != nil {
			return err
		}
		input = entry.Temp
	} else {
		input = bytes.NewReader(entry.Data)
	}
	if progress != nil {
		input = progress.Reader(input)
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
						cleanupWorkingTemp(files[p].Temp)
						delete(files, p)
					}
				}
			} else {
				victim := path.Join(dir, strings.TrimPrefix(base, ".wh."))
				cleanupWorkingTemp(files[victim].Temp)
				delete(files, victim)
				for p := range files {
					if strings.HasPrefix(p, victim+"/") {
						cleanupWorkingTemp(files[p].Temp)
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
		var rpmTemp *os.File
		if sbomRPMDBPath(name) {
			rpmTemp, err = createWorkingTemp("rpmdb-*")
			if err == nil {
				_, err = io.Copy(io.MultiWriter(hash, rpmTemp), tr)
			}
			if err == nil {
				err = rpmTemp.Sync()
			}
		} else if h.Size <= maxContainerMetadata && sbomInteresting(name) {
			data, err = io.ReadAll(io.TeeReader(tr, hash))
		} else {
			_, err = io.Copy(hash, tr)
		}
		if err != nil {
			cleanupWorkingTemp(rpmTemp)
			return err
		}
		cleanupWorkingTemp(files[name].Temp)
		files[name] = sbomFile{Path: name, Size: h.Size, SHA256: hex.EncodeToString(hash.Sum(nil)), Data: data, Temp: rpmTemp, Layer: layer}
	}
}

func cleanupSBOMTemps(files map[string]sbomFile) {
	for _, file := range files {
		cleanupWorkingTemp(file.Temp)
	}
}

func sbomRPMDBPath(filePath string) bool {
	filePath = strings.ToLower(strings.TrimPrefix(filePath, "/"))
	base := path.Base(filePath)
	if base != "packages" && base != "packages.db" && base != "rpmdb.sqlite" {
		return false
	}
	dir := path.Dir(filePath)
	return dir == "var/lib/rpm" || dir == "usr/share/rpm" || dir == "usr/lib/sysimage/rpm" || strings.HasSuffix(dir, "/var/lib/rpm") || strings.HasSuffix(dir, "/usr/share/rpm") || strings.HasSuffix(dir, "/usr/lib/sysimage/rpm")
}

func sbomInteresting(p string) bool {
	p = strings.ToLower(p)
	base := path.Base(p)
	if p == "var/lib/dpkg/status" || p == "lib/apk/db/installed" || strings.HasSuffix(p, "/os-release") {
		return true
	}
	switch base {
	case "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "go.mod", "requirements.txt", "pipfile.lock", "poetry.lock", "uv.lock", "cargo.lock", "pom.properties", "composer.lock", "gemfile.lock", "project.assets.json", "packages.lock.json", "package.resolved", "pubspec.lock", "pyvenv.cfg", ".python-version", "node_version.h":
		return true
	}
	return strings.HasSuffix(p, ".dist-info/metadata") || strings.HasSuffix(p, ".egg-info/pkg-info") || strings.HasSuffix(p, ".deps.json") || strings.HasSuffix(p, ".gemspec") || (base == "package.json" && strings.Contains(p, "node_modules/")) || (strings.HasSuffix(p, ".json") && strings.Contains(p, "/conda-meta/"))
}

func catalogSBOMPackages(files []sbomFile) ([]sbomPackage, string, string, []string) {
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
	var warnings []string
	for _, f := range files {
		if f.Temp != nil && sbomRPMDBPath(f.Path) {
			db, err := rpmdb.Open(f.Temp.Name())
			if err != nil {
				uiVerbosef("SBOM RPM database skipped %s: %v", f.Path, err)
				warnings = append(warnings, fmt.Sprintf("RPM database %s could not be decoded: %v", f.Path, err))
			} else {
				packages, listErr := db.ListPackages()
				_ = db.Close()
				if listErr != nil {
					uiVerbosef("SBOM RPM database skipped %s: %v", f.Path, listErr)
					warnings = append(warnings, fmt.Sprintf("RPM database %s could not be listed: %v", f.Path, listErr))
				} else {
					for _, p := range packages {
						if p == nil {
							continue
						}
						packageVersion := p.Version
						if p.Release != "" {
							packageVersion += "-" + p.Release
						}
						add(sbomPackage{Name: p.Name, Version: packageVersion, Architecture: p.Arch, License: p.License, Type: "rpm", Source: f.Path})
					}
				}
			}
		}
		if version, ok := sbomPyenvRuntime(f.Path); ok {
			add(sbomPackage{Name: "python", Version: version, Type: "generic", PURL: "pkg:generic/python@" + url.PathEscape(version), Source: f.Path})
		}
		if len(f.Data) == 0 {
			continue
		}
		lower := strings.ToLower(f.Path)
		if catalogExtraSBOMFile(f, add) {
			continue
		}
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
		case path.Base(lower) == "package.json" && strings.Contains(lower, "node_modules/"):
			var manifest struct {
				Name    string `json:"name"`
				Version string `json:"version"`
				License any    `json:"license"`
			}
			if json.Unmarshal(f.Data, &manifest) == nil {
				license := ""
				switch value := manifest.License.(type) {
				case string:
					license = value
				case map[string]any:
					license, _ = value["type"].(string)
				}
				add(sbomPackage{Name: manifest.Name, Version: manifest.Version, License: license, Type: "npm", Source: f.Path})
			}
		case path.Base(lower) == "go.mod":
			scanSBOMGoMod(string(f.Data), f.Path, add)
		case path.Base(lower) == "requirements.txt":
			scanSBOMRequirements(string(f.Data), f.Path, add)
		case strings.HasSuffix(lower, ".dist-info/metadata"):
			if p := sbomParagraphs(f.Data); len(p) > 0 {
				add(sbomPackage{Name: p[0]["Name"], Version: p[0]["Version"], License: p[0]["License"], Type: "pypi", Source: f.Path})
			}
		case path.Base(lower) == "pyvenv.cfg":
			v := sbomKeyValues(f.Data, "=")
			pythonVersion := strings.TrimSpace(v["version"])
			if pythonVersion != "" {
				add(sbomPackage{Name: "python", Version: pythonVersion, Type: "generic", PURL: "pkg:generic/python@" + url.PathEscape(pythonVersion), Source: f.Path})
			}
		case path.Base(lower) == "node_version.h":
			if nodeVersion := sbomNodeHeaderVersion(string(f.Data)); nodeVersion != "" {
				add(sbomPackage{Name: "node", Version: nodeVersion, Type: "generic", PURL: "pkg:generic/node@" + url.PathEscape(nodeVersion), Source: f.Path})
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
	return out, osName, osVersion, warnings
}

func sbomPyenvRuntime(filePath string) (string, bool) {
	parts := strings.Split(strings.Trim(filePath, "/"), "/")
	for i := 0; i+4 < len(parts); i++ {
		root := strings.ToLower(parts[i])
		if (root == ".pyenv" || root == "pyenv") && parts[i+1] == "versions" && parts[i+2] != "" && parts[i+3] == "bin" {
			binary := strings.ToLower(parts[i+4])
			if binary == "python" || binary == "python3" || strings.HasPrefix(binary, "python3.") || strings.HasPrefix(binary, "pypy") {
				return parts[i+2], true
			}
		}
	}
	return "", false
}

func sbomNodeHeaderVersion(contents string) string {
	values := map[string]string{}
	for _, line := range strings.Split(contents, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "#define" {
			switch fields[1] {
			case "NODE_MAJOR_VERSION", "NODE_MINOR_VERSION", "NODE_PATCH_VERSION":
				values[fields[1]] = strings.Trim(fields[2], `"`)
			}
		}
	}
	if values["NODE_MAJOR_VERSION"] == "" || values["NODE_MINOR_VERSION"] == "" || values["NODE_PATCH_VERSION"] == "" {
		return ""
	}
	return values["NODE_MAJOR_VERSION"] + "." + values["NODE_MINOR_VERSION"] + "." + values["NODE_PATCH_VERSION"]
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
	comment := fmt.Sprintf("Sugyeol scanned %s image; platform: %s; operating system: %s %s", r.SourceType, formatOCIPlatform(r.Platform), r.OSName, r.OSVersion)
	if r.ManifestDigest != "" {
		comment += "; OCI manifest digest: " + r.ManifestDigest
	}
	comment += "; catalog coverage: deb, apk, rpm, npm/yarn/pnpm, Python/pyenv/venv/conda, Go, Cargo, Maven, Ruby, Composer, .NET, Swift, Dart"
	if len(r.Warnings) > 0 {
		comment += "; scan warnings: " + strings.Join(r.Warnings, " | ")
	}
	root := spdxPackage{SPDXID: "SPDXRef-Image", Name: r.Name, DownloadLocation: "NOASSERTION", FilesAnalyzed: false,
		LicenseConcluded: "NOASSERTION", LicenseDeclared: "NOASSERTION", CopyrightText: "NOASSERTION",
		Checksums:      []spdxChecksum{{Algorithm: "SHA256", Value: r.SourceHash}},
		PackageComment: comment}
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
