package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

type pulledBlob struct {
	descriptor ociDescriptor
	data       []byte
}

type registryPuller struct {
	ref           parsedImageReference
	client        *http.Client
	authorization string
	blobs         map[string]pulledBlob
	allPlatforms  bool
	platform      ociPlatform
}

func imagePullCommand(args []string) error {
	fs := flag.NewFlagSet("image pull", flag.ContinueOnError)
	out := fs.String("out", "", "output OCI image-layout .tar or .tgz")
	platform := fs.String("platform", runtime.GOOS+"/"+runtime.GOARCH, "platform os/arch[/variant]")
	allPlatforms := fs.Bool("all-platforms", false, "download every platform from an image index")
	gzipOutput := fs.Bool("gzip", false, "gzip-compress the outer OCI archive")
	signAfterPull := fs.Bool("sign", false, "sign the verified local archive after download")
	metaOut := fs.String("meta", "", "signature metadata output path (requires sign)")
	label := fs.String("label", "", "optional signed role/purpose label")
	fs.StringVar(out, "o", "", "output OCI image-layout .tar or .tgz")
	fs.StringVar(platform, "p", runtime.GOOS+"/"+runtime.GOARCH, "platform os/arch[/variant]")
	fs.BoolVar(allPlatforms, "a", false, "download every platform from an image index")
	fs.BoolVar(gzipOutput, "z", false, "gzip-compress the outer OCI archive")
	fs.BoolVar(signAfterPull, "S", false, "sign the verified local archive after download")
	fs.StringVar(metaOut, "m", "", "signature metadata output path (requires sign)")
	fs.StringVar(label, "l", "", "optional signed role/purpose label")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: sugyeol image pull [-o image.tar] [-p linux/amd64|-a] <registry/repository:tag>")
	}
	if *metaOut != "" && !*signAfterPull {
		return fmt.Errorf("--meta requires --sign")
	}
	wanted, err := parseOCIPlatform(*platform)
	if err != nil {
		return err
	}
	ref, err := parseImageReference(fs.Arg(0))
	if err != nil {
		return err
	}
	if *out == "" {
		base := filepath.Base(ref.Repository) + "-" + strings.NewReplacer(":", "-", "@", "-").Replace(ref.Identifier)
		if *gzipOutput {
			*out = base + ".oci.tgz"
		} else {
			*out = base + ".oci.tar"
		}
	}
	if strings.HasSuffix(strings.ToLower(*out), ".tgz") || strings.HasSuffix(strings.ToLower(*out), ".tar.gz") {
		*gzipOutput = true
	}
	uiDebugf("image pull reference=%q output=%q platform=%q all_platforms=%t gzip=%t sign=%t", fs.Arg(0), *out, *platform, *allPlatforms, *gzipOutput, *signAfterPull)
	ctx, cancel := context.WithTimeout(commandContext, 24*time.Hour)
	defer cancel()
	puller := &registryPuller{ref: ref, client: &http.Client{Timeout: 0}, blobs: make(map[string]pulledBlob), allPlatforms: *allPlatforms, platform: wanted}
	resolveProgress := newProgress(tr("progress_resolve_image"), 0)
	roots, err := puller.collectImage(ctx)
	resolveProgress.Finish(err)
	if err != nil {
		return err
	}
	if err := puller.writeArchive(ctx, *out, fs.Arg(0), roots, *gzipOutput); err != nil {
		return err
	}
	subject, err := inspectContainerArchive(*out)
	if err != nil {
		return fmt.Errorf("verify downloaded image archive: %w", err)
	}
	fmt.Printf("container image downloaded: %s\narchive: %s\nformat: %s\nsha256: %s\n", fs.Arg(0), *out, subject.ArchiveFormat, subject.ArchiveSHA256)
	if *signAfterPull {
		signArgs := make([]string, 0, 5)
		if *metaOut != "" {
			signArgs = append(signArgs, "-o", *metaOut)
		}
		if *label != "" {
			signArgs = append(signArgs, "-l", *label)
		}
		signArgs = append(signArgs, *out)
		return imageSignCommand(signArgs)
	}
	return nil
}

func parseOCIPlatform(value string) (ociPlatform, error) {
	parts := strings.Split(strings.TrimSpace(value), "/")
	if len(parts) < 2 || len(parts) > 3 || parts[0] == "" || parts[1] == "" {
		return ociPlatform{}, fmt.Errorf("platform must be os/arch[/variant]")
	}
	p := ociPlatform{OS: parts[0], Architecture: parts[1]}
	if len(parts) == 3 {
		p.Variant = parts[2]
	}
	return p, nil
}

func (p *registryPuller) collectImage(ctx context.Context) ([]ociDescriptor, error) {
	rootData, rootMedia, rootDigest, err := p.fetchManifest(ctx, p.ref.Identifier)
	if err != nil {
		return nil, err
	}
	root := ociDescriptor{MediaType: rootMedia, Digest: rootDigest, Size: int64(len(rootData))}
	if rootMedia == ociIndexMediaType || rootMedia == dockerIndexMediaType {
		var index ociIndex
		if err := json.Unmarshal(rootData, &index); err != nil || index.SchemaVersion != 2 {
			return nil, fmt.Errorf("invalid remote image index")
		}
		if p.allPlatforms {
			p.blobs[root.Digest] = pulledBlob{descriptor: root, data: rootData}
			if err := p.collectDescriptorChildren(ctx, root, rootData); err != nil {
				return nil, err
			}
			return []ociDescriptor{root}, nil
		}
		matches := make([]ociDescriptor, 0, 1)
		for _, d := range index.Manifests {
			if d.Platform != nil && d.Platform.OS == p.platform.OS && d.Platform.Architecture == p.platform.Architecture && (p.platform.Variant == "" || d.Platform.Variant == p.platform.Variant) {
				matches = append(matches, d)
			}
		}
		if len(matches) != 1 {
			return nil, fmt.Errorf("platform %s/%s/%s matched %d manifests; use --all-platforms or a more specific --platform", p.platform.OS, p.platform.Architecture, p.platform.Variant, len(matches))
		}
		if err := p.collectDescriptor(ctx, matches[0]); err != nil {
			return nil, err
		}
		return matches, nil
	}
	p.blobs[root.Digest] = pulledBlob{descriptor: root, data: rootData}
	if err := p.collectDescriptorChildren(ctx, root, rootData); err != nil {
		return nil, err
	}
	return []ociDescriptor{root}, nil
}

func (p *registryPuller) collectDescriptor(ctx context.Context, descriptor ociDescriptor) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !digestPattern.MatchString(descriptor.Digest) || descriptor.Size < 0 {
		return fmt.Errorf("invalid remote descriptor %q", descriptor.Digest)
	}
	if existing, ok := p.blobs[descriptor.Digest]; ok {
		if existing.descriptor.Size != descriptor.Size {
			return fmt.Errorf("conflicting descriptor size for %s", descriptor.Digest)
		}
		return nil
	}
	if descriptor.MediaType != ociIndexMediaType && descriptor.MediaType != dockerIndexMediaType && descriptor.MediaType != ociManifestMediaType && descriptor.MediaType != dockerManifestMediaType {
		p.blobs[descriptor.Digest] = pulledBlob{descriptor: descriptor}
		return nil
	}
	data, mediaType, digest, err := p.fetchManifest(ctx, descriptor.Digest)
	if err != nil {
		return err
	}
	if digest != descriptor.Digest || int64(len(data)) != descriptor.Size || mediaType != descriptor.MediaType {
		return fmt.Errorf("remote descriptor changed while pulling: %s", descriptor.Digest)
	}
	p.blobs[descriptor.Digest] = pulledBlob{descriptor: descriptor, data: data}
	return p.collectDescriptorChildren(ctx, descriptor, data)
}

func (p *registryPuller) collectDescriptorChildren(ctx context.Context, descriptor ociDescriptor, data []byte) error {
	switch descriptor.MediaType {
	case ociIndexMediaType, dockerIndexMediaType:
		var index ociIndex
		if err := json.Unmarshal(data, &index); err != nil || index.SchemaVersion != 2 {
			return fmt.Errorf("invalid nested image index %s", descriptor.Digest)
		}
		for _, child := range index.Manifests {
			if err := p.collectDescriptor(ctx, child); err != nil {
				return err
			}
		}
	case ociManifestMediaType, dockerManifestMediaType:
		var manifest ociManifest
		if err := json.Unmarshal(data, &manifest); err != nil || manifest.SchemaVersion != 2 {
			return fmt.Errorf("invalid image manifest %s", descriptor.Digest)
		}
		if err := p.collectDescriptor(ctx, manifest.Config); err != nil {
			return err
		}
		for _, layer := range manifest.Layers {
			if err := p.collectDescriptor(ctx, layer); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *registryPuller) fetchManifest(ctx context.Context, identifier string) ([]byte, string, string, error) {
	resp, err := p.get(ctx, "/v2/"+p.ref.Repository+"/manifests/"+identifier, manifestAccept)
	if err != nil {
		return nil, "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", "", fmt.Errorf("registry manifest %s: %s", identifier, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxContainerMetadata+1))
	if err != nil || int64(len(data)) > maxContainerMetadata {
		return nil, "", "", fmt.Errorf("read registry manifest %s: %w", identifier, err)
	}
	sum := sha256.Sum256(data)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	if header := resp.Header.Get("Docker-Content-Digest"); header != "" && header != digest {
		return nil, "", "", fmt.Errorf("registry manifest digest mismatch: %s != %s", header, digest)
	}
	mediaType := strings.TrimSpace(strings.Split(resp.Header.Get("Content-Type"), ";")[0])
	if mediaType == "" {
		var envelope struct {
			MediaType string `json:"mediaType"`
		}
		_ = json.Unmarshal(data, &envelope)
		mediaType = envelope.MediaType
	}
	switch mediaType {
	case ociIndexMediaType, dockerIndexMediaType, ociManifestMediaType, dockerManifestMediaType:
	default:
		return nil, "", "", fmt.Errorf("unsupported registry manifest media type %q", mediaType)
	}
	return data, mediaType, digest, nil
}

func (p *registryPuller) get(ctx context.Context, endpointPath, accept string) (*http.Response, error) {
	scheme := "https"
	if strings.HasPrefix(p.ref.endpoint(), "http://") {
		scheme = "http"
	}
	endpoint := scheme + "://" + p.ref.Registry + endpointPath
	request := func(auth string) (*http.Response, error) {
		uiDebugf("registry GET %s authenticated=%t", endpoint, auth != "")
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "sugyeol-container-pull")
		req.Header.Set("Accept-Encoding", "identity")
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		return p.client.Do(req)
	}
	resp, err := request(p.authorization)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}
	challenge := resp.Header.Get("WWW-Authenticate")
	resp.Body.Close()
	p.authorization, err = registryAuthorization(ctx, p.client, p.ref, challenge)
	if err != nil {
		return nil, err
	}
	return request(p.authorization)
}

func (p *registryPuller) writeArchive(ctx context.Context, output, reference string, roots []ociDescriptor, gzipOutput bool) (resultErr error) {
	if _, err := os.Lstat(output); err == nil {
		return fmt.Errorf("output already exists: %s", output)
	} else if !os.IsNotExist(err) {
		return err
	}
	dir := filepath.Dir(output)
	if err := os.MkdirAll(dir, 0755); err != nil && dir != "." {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".sugyeol-image-pull-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		tmp.Close()
		if !ok {
			os.Remove(tmpName)
		}
	}()
	var outer io.Writer = tmp
	var gz *gzip.Writer
	if gzipOutput {
		gz, err = gzip.NewWriterLevel(tmp, gzip.BestSpeed)
		if err != nil {
			return err
		}
		outer = gz
	}
	tw := tar.NewWriter(outer)
	layout := []byte("{\"imageLayoutVersion\":\"1.0.0\"}\n")
	index := ociIndex{SchemaVersion: 2, MediaType: ociIndexMediaType, Manifests: append([]ociDescriptor(nil), roots...)}
	for i := range index.Manifests {
		if index.Manifests[i].Annotations == nil {
			index.Manifests[i].Annotations = make(map[string]string)
		}
		index.Manifests[i].Annotations["org.opencontainers.image.ref.name"] = reference
	}
	indexBytes, err := json.Marshal(index)
	if err != nil {
		return err
	}
	indexBytes = append(indexBytes, '\n')
	if err := writeContainerTarBytes(tw, "oci-layout", layout); err != nil {
		return err
	}
	if err := writeContainerTarBytes(tw, "index.json", indexBytes); err != nil {
		return err
	}
	digests := make([]string, 0, len(p.blobs))
	var total int64
	for digest := range p.blobs {
		digests = append(digests, digest)
		size := p.blobs[digest].descriptor.Size
		if size < 0 || total > (1<<63-1)-size {
			return fmt.Errorf("container image content size overflow")
		}
		total += size
	}
	sort.Strings(digests)
	progress := newProgress(tr("progress_pull_blobs"), total)
	defer func() { progress.Finish(resultErr) }()
	for _, digest := range digests {
		if err := ctx.Err(); err != nil {
			return err
		}
		blob := p.blobs[digest]
		name := "blobs/sha256/" + strings.TrimPrefix(digest, "sha256:")
		uiVerbosef("blob %s (%s)", digest, humanSize(blob.descriptor.Size))
		if len(blob.data) > 0 {
			if int64(len(blob.data)) != blob.descriptor.Size {
				return fmt.Errorf("blob size mismatch: %s", digest)
			}
			if err := writeContainerTarBytes(tw, name, blob.data); err != nil {
				return err
			}
			progress.Add(int64(len(blob.data)))
			continue
		}
		resp, err := p.get(ctx, "/v2/"+p.ref.Repository+"/blobs/"+digest, "application/octet-stream")
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return fmt.Errorf("registry blob %s: %s", digest, resp.Status)
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: blob.descriptor.Size, Typeflag: tar.TypeReg}); err != nil {
			resp.Body.Close()
			return err
		}
		h := sha256.New()
		n, copyErr := io.CopyN(io.MultiWriter(tw, h, progress), resp.Body, blob.descriptor.Size)
		var extra [1]byte
		extraN, extraErr := resp.Body.Read(extra[:])
		closeErr := resp.Body.Close()
		if copyErr != nil || n != blob.descriptor.Size || (extraN != 0 && extraErr == nil) {
			return fmt.Errorf("registry blob size mismatch %s: %d/%d", digest, n+int64(extraN), blob.descriptor.Size)
		}
		if closeErr != nil {
			return closeErr
		}
		if "sha256:"+hex.EncodeToString(h.Sum(nil)) != digest {
			return fmt.Errorf("registry blob digest mismatch: %s", digest)
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if gz != nil {
		if err := gz.Close(); err != nil {
			return err
		}
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0644); err != nil {
		return err
	}
	if err := os.Link(tmpName, output); err != nil {
		return err
	}
	if err := os.Remove(tmpName); err != nil {
		return err
	}
	ok = true
	progress.Finish(nil)
	return nil
}

func writeContainerTarBytes(tw *tar.Writer, name string, data []byte) error {
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}
