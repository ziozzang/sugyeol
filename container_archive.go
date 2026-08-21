package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

const (
	ociIndexMediaType             = "application/vnd.oci.image.index.v1+json"
	ociManifestMediaType          = "application/vnd.oci.image.manifest.v1+json"
	dockerIndexMediaType          = "application/vnd.docker.distribution.manifest.list.v2+json"
	dockerManifestMediaType       = "application/vnd.docker.distribution.manifest.v2+json"
	containerArchiveFormat        = "sugyeol-container-archive"
	maxContainerMetadata    int64 = 16 << 20
)

type ociPlatform struct {
	Architecture string `json:"architecture,omitempty"`
	OS           string `json:"os,omitempty"`
	Variant      string `json:"variant,omitempty"`
}

type ociDescriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Platform    *ociPlatform      `json:"platform,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type ociIndex struct {
	SchemaVersion int             `json:"schemaVersion"`
	MediaType     string          `json:"mediaType,omitempty"`
	Manifests     []ociDescriptor `json:"manifests"`
}

type ociManifest struct {
	SchemaVersion int             `json:"schemaVersion"`
	MediaType     string          `json:"mediaType,omitempty"`
	Config        ociDescriptor   `json:"config"`
	Layers        []ociDescriptor `json:"layers"`
}

type localImageSubject struct {
	Format          string          `json:"format"`
	Version         int             `json:"version"`
	ArchiveFormat   string          `json:"archive_format"`
	ArchiveFile     string          `json:"archive_file"`
	ArchiveSize     int64           `json:"archive_size"`
	ArchiveSHA256   string          `json:"archive_sha256"`
	Compression     string          `json:"compression"`
	IndexSHA256     string          `json:"index_sha256,omitempty"`
	References      []string        `json:"references,omitempty"`
	RootDescriptors []ociDescriptor `json:"root_descriptors,omitempty"`
}

type archiveEntry struct {
	size int64
	data []byte
}

type byteCounter struct{ n int64 }

func (c *byteCounter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}

func inspectContainerArchive(filePath string) (localImageSubject, error) {
	info, err := os.Lstat(filePath)
	if err != nil {
		return localImageSubject{}, err
	}
	if !info.Mode().IsRegular() {
		return localImageSubject{}, fmt.Errorf("container archive must be a regular file")
	}
	f, err := os.Open(filePath)
	if err != nil {
		return localImageSubject{}, err
	}
	defer f.Close()
	h := sha256.New()
	counter := &byteCounter{}
	br := bufio.NewReader(io.TeeReader(f, io.MultiWriter(h, counter)))
	compression := "none"
	var archiveReader io.Reader = br
	var gz *gzip.Reader
	magic, _ := br.Peek(2)
	if len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err = gzip.NewReader(br)
		if err != nil {
			return localImageSubject{}, fmt.Errorf("invalid gzip container archive: %w", err)
		}
		archiveReader = gz
		compression = "gzip"
	}

	entries, small, err := scanContainerTar(archiveReader)
	if err != nil {
		return localImageSubject{}, err
	}
	if gz != nil {
		if _, err := io.Copy(io.Discard, gz); err != nil {
			return localImageSubject{}, fmt.Errorf("finish gzip container archive: %w", err)
		}
		if err := gz.Close(); err != nil {
			return localImageSubject{}, err
		}
	}
	if _, err := io.Copy(io.Discard, br); err != nil {
		return localImageSubject{}, err
	}
	postInfo, err := f.Stat()
	if err != nil {
		return localImageSubject{}, err
	}
	if postInfo.Size() != counter.n || postInfo.Size() != info.Size() || !postInfo.ModTime().Equal(info.ModTime()) {
		return localImageSubject{}, fmt.Errorf("container archive changed while it was being inspected")
	}
	subject := localImageSubject{Format: containerArchiveFormat, Version: 1, ArchiveFile: filepath.Base(filePath),
		ArchiveSize: counter.n, ArchiveSHA256: hex.EncodeToString(h.Sum(nil)), Compression: compression}
	if layoutBytes, ok := small["oci-layout"]; ok {
		if err := inspectOCILayout(entries, small, layoutBytes, &subject); err != nil {
			return localImageSubject{}, err
		}
		return subject, nil
	}
	if manifestBytes, ok := small["manifest.json"]; ok {
		if err := inspectDockerArchive(entries, manifestBytes, &subject); err != nil {
			return localImageSubject{}, err
		}
		return subject, nil
	}
	return localImageSubject{}, fmt.Errorf("not an OCI image-layout or docker-save archive")
}

func scanContainerTar(r io.Reader) (map[string]archiveEntry, map[string][]byte, error) {
	tr := tar.NewReader(r)
	entries := make(map[string]archiveEntry)
	small := make(map[string][]byte)
	var smallTotal int64
	for count := 0; ; count++ {
		if count > 100000 {
			return nil, nil, fmt.Errorf("container archive has too many entries")
		}
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("read container tar: %w", err)
		}
		name := strings.TrimPrefix(path.Clean(strings.ReplaceAll(hdr.Name, "\\", "/")), "./")
		if name == "" || name == "." || strings.HasPrefix(name, "/") || name == ".." || strings.HasPrefix(name, "../") {
			return nil, nil, fmt.Errorf("unsafe container archive path %q", hdr.Name)
		}
		if _, exists := entries[name]; exists {
			return nil, nil, fmt.Errorf("duplicate container archive entry %q", name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			entries[name] = archiveEntry{}
			continue
		case tar.TypeReg, tar.TypeRegA:
		default:
			return nil, nil, fmt.Errorf("container archive links and special entries are not allowed: %q", name)
		}
		if hdr.Size < 0 {
			return nil, nil, fmt.Errorf("negative container archive entry size")
		}
		entry := archiveEntry{size: hdr.Size}
		capture := name == "oci-layout" || name == "index.json" || name == "manifest.json" || (strings.HasPrefix(name, "blobs/sha256/") && hdr.Size <= maxContainerMetadata)
		var dst io.Writer = io.Discard
		var data []byte
		if capture {
			if smallTotal+hdr.Size > 128<<20 {
				return nil, nil, fmt.Errorf("container archive metadata exceeds 128 MiB")
			}
			data = make([]byte, hdr.Size)
			dst = bytesWriter(data)
			smallTotal += hdr.Size
		}
		blobHash := sha256.New()
		if strings.HasPrefix(name, "blobs/sha256/") {
			dst = io.MultiWriter(dst, blobHash)
		}
		if n, err := io.Copy(dst, tr); err != nil || n != hdr.Size {
			return nil, nil, fmt.Errorf("read container archive entry %q: %d/%d bytes: %w", name, n, hdr.Size, err)
		}
		if strings.HasPrefix(name, "blobs/sha256/") {
			encoded := strings.TrimPrefix(name, "blobs/sha256/")
			if len(encoded) != 64 || hex.EncodeToString(blobHash.Sum(nil)) != encoded {
				return nil, nil, fmt.Errorf("OCI blob digest mismatch: %s", name)
			}
		}
		entry.data = data
		entries[name] = entry
		if capture {
			small[name] = data
		}
	}
	return entries, small, nil
}

type fixedSliceWriter struct {
	b   []byte
	off int
}

func bytesWriter(b []byte) io.Writer { return &fixedSliceWriter{b: b} }
func (w *fixedSliceWriter) Write(p []byte) (int, error) {
	n := copy(w.b[w.off:], p)
	w.off += n
	if n != len(p) {
		return n, io.ErrShortWrite
	}
	return n, nil
}

func inspectOCILayout(entries map[string]archiveEntry, small map[string][]byte, layoutBytes []byte, subject *localImageSubject) error {
	var layout struct {
		ImageLayoutVersion string `json:"imageLayoutVersion"`
	}
	if err := json.Unmarshal(layoutBytes, &layout); err != nil || layout.ImageLayoutVersion == "" {
		return fmt.Errorf("invalid oci-layout")
	}
	indexBytes := small["index.json"]
	if len(indexBytes) == 0 {
		return fmt.Errorf("OCI image layout has no index.json")
	}
	var index ociIndex
	if err := json.Unmarshal(indexBytes, &index); err != nil || index.SchemaVersion != 2 || len(index.Manifests) == 0 {
		return fmt.Errorf("invalid OCI index.json")
	}
	visited := make(map[string]bool)
	for _, descriptor := range index.Manifests {
		if err := validateOCIDescriptorGraph(descriptor, entries, small, visited); err != nil {
			return err
		}
	}
	refs := make([]string, 0)
	for _, descriptor := range index.Manifests {
		if ref := descriptor.Annotations["org.opencontainers.image.ref.name"]; ref != "" {
			refs = append(refs, ref)
		}
	}
	sort.Strings(refs)
	sum := sha256.Sum256(indexBytes)
	subject.ArchiveFormat = "oci-image-layout"
	subject.IndexSHA256 = hex.EncodeToString(sum[:])
	subject.References = refs
	subject.RootDescriptors = index.Manifests
	return nil
}

func validateOCIDescriptorGraph(d ociDescriptor, entries map[string]archiveEntry, small map[string][]byte, visited map[string]bool) error {
	if !digestPattern.MatchString(d.Digest) || d.Size < 0 {
		return fmt.Errorf("invalid OCI descriptor %q", d.Digest)
	}
	name := "blobs/sha256/" + strings.TrimPrefix(d.Digest, "sha256:")
	entry, ok := entries[name]
	if !ok || entry.size != d.Size {
		return fmt.Errorf("missing or incorrectly sized OCI blob %s", d.Digest)
	}
	if visited[d.Digest] {
		return nil
	}
	visited[d.Digest] = true
	switch d.MediaType {
	case ociIndexMediaType, dockerIndexMediaType:
		data := small[name]
		if len(data) == 0 {
			return fmt.Errorf("OCI image index is too large to validate: %s", d.Digest)
		}
		var index ociIndex
		if err := json.Unmarshal(data, &index); err != nil || index.SchemaVersion != 2 {
			return fmt.Errorf("invalid OCI image index %s", d.Digest)
		}
		for _, child := range index.Manifests {
			if err := validateOCIDescriptorGraph(child, entries, small, visited); err != nil {
				return err
			}
		}
	case ociManifestMediaType, dockerManifestMediaType:
		data := small[name]
		if len(data) == 0 {
			return fmt.Errorf("OCI image manifest is too large to validate: %s", d.Digest)
		}
		var manifest ociManifest
		if err := json.Unmarshal(data, &manifest); err != nil || manifest.SchemaVersion != 2 {
			return fmt.Errorf("invalid OCI image manifest %s", d.Digest)
		}
		if err := validateOCIDescriptorGraph(manifest.Config, entries, small, visited); err != nil {
			return err
		}
		for _, layer := range manifest.Layers {
			if err := validateOCIDescriptorGraph(layer, entries, small, visited); err != nil {
				return err
			}
		}
	}
	return nil
}

func inspectDockerArchive(entries map[string]archiveEntry, manifestBytes []byte, subject *localImageSubject) error {
	var manifests []struct {
		Config   string   `json:"Config"`
		RepoTags []string `json:"RepoTags"`
		Layers   []string `json:"Layers"`
	}
	if err := json.Unmarshal(manifestBytes, &manifests); err != nil || len(manifests) == 0 {
		return fmt.Errorf("invalid docker-save manifest.json")
	}
	refs := make([]string, 0)
	for _, manifest := range manifests {
		for _, name := range append([]string{manifest.Config}, manifest.Layers...) {
			clean := strings.TrimPrefix(path.Clean(strings.ReplaceAll(name, "\\", "/")), "./")
			if clean == "" || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
				return fmt.Errorf("unsafe docker archive reference %q", name)
			}
			if _, ok := entries[clean]; !ok {
				return fmt.Errorf("docker archive entry is missing: %s", clean)
			}
		}
		refs = append(refs, manifest.RepoTags...)
	}
	sort.Strings(refs)
	subject.ArchiveFormat = "docker-save"
	subject.References = refs
	return nil
}
