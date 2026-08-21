package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const manifestAccept = "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json"

var (
	repositoryPattern     = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$`)
	tagPattern            = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)
	digestPattern         = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	challengeFieldPattern = regexp.MustCompile(`([A-Za-z]+)="([^"]*)"`)
)

type parsedImageReference struct {
	Original   string
	Registry   string
	Repository string
	Identifier string
}

func parseImageReference(input string) (parsedImageReference, error) {
	input = strings.TrimSpace(input)
	if input == "" || strings.Contains(input, "://") {
		return parsedImageReference{}, fmt.Errorf("invalid container image reference %q", input)
	}
	namePart, identifier := input, ""
	if at := strings.LastIndex(input, "@"); at >= 0 {
		namePart, identifier = input[:at], input[at+1:]
		if !digestPattern.MatchString(identifier) {
			return parsedImageReference{}, fmt.Errorf("only sha256 image digests are supported")
		}
	} else {
		lastSlash, lastColon := strings.LastIndex(input, "/"), strings.LastIndex(input, ":")
		if lastColon > lastSlash {
			namePart, identifier = input[:lastColon], input[lastColon+1:]
		} else {
			identifier = "latest"
		}
		if !tagPattern.MatchString(identifier) {
			return parsedImageReference{}, fmt.Errorf("invalid image tag %q", identifier)
		}
	}
	parts := strings.Split(namePart, "/")
	registry, repository := "registry-1.docker.io", namePart
	if len(parts) > 1 && (strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":") || parts[0] == "localhost") {
		registry, repository = parts[0], strings.Join(parts[1:], "/")
	} else if len(parts) == 1 {
		repository = "library/" + repository
	}
	if registry == "" || !repositoryPattern.MatchString(repository) {
		return parsedImageReference{}, fmt.Errorf("invalid image repository %q", repository)
	}
	if registry == "docker.io" || registry == "index.docker.io" {
		registry = "registry-1.docker.io"
	}
	return parsedImageReference{Original: input, Registry: registry, Repository: repository, Identifier: identifier}, nil
}

func (r parsedImageReference) endpoint() string {
	scheme := "https"
	host, _, _ := net.SplitHostPort(r.Registry)
	if host == "" {
		host = r.Registry
	}
	if host == "localhost" || net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback() {
		scheme = "http"
	}
	return scheme + "://" + r.Registry + "/v2/" + r.Repository + "/manifests/" + r.Identifier
}

type registryCredential struct{ Username, Password, IdentityToken string }

func dockerCredential(registry string) registryCredential {
	dir := os.Getenv("DOCKER_CONFIG")
	if dir == "" {
		if home, err := os.UserHomeDir(); err == nil {
			dir = filepath.Join(home, ".docker")
		}
	}
	b, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		return registryCredential{}
	}
	var cfg struct {
		Auths map[string]struct {
			Auth          string `json:"auth"`
			IdentityToken string `json:"identitytoken"`
		} `json:"auths"`
	}
	if json.Unmarshal(b, &cfg) != nil {
		return registryCredential{}
	}
	candidates := []string{registry, "https://" + registry, "http://" + registry}
	if registry == "registry-1.docker.io" {
		candidates = append(candidates, "https://index.docker.io/v1/", "index.docker.io")
	}
	for _, key := range candidates {
		a, ok := cfg.Auths[key]
		if !ok {
			continue
		}
		cred := registryCredential{IdentityToken: a.IdentityToken}
		if raw, err := base64.StdEncoding.DecodeString(a.Auth); err == nil {
			if user, pass, ok := strings.Cut(string(raw), ":"); ok {
				cred.Username, cred.Password = user, pass
			}
		}
		return cred
	}
	return registryCredential{}
}

type remoteImageSubject struct {
	Format            string `json:"format"`
	Version           int    `json:"version"`
	Reference         string `json:"reference"`
	ResolvedReference string `json:"resolved_reference"`
	Registry          string `json:"registry"`
	Repository        string `json:"repository"`
	Digest            string `json:"digest"`
	MediaType         string `json:"media_type"`
	ManifestSize      int64  `json:"manifest_size"`
	ManifestSHA256    string `json:"manifest_sha256"`
}

func resolveRemoteImage(ctx context.Context, client *http.Client, input string) (remoteImageSubject, error) {
	ref, err := parseImageReference(input)
	if err != nil {
		return remoteImageSubject{}, err
	}
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := manifestRequest(ctx, client, ref, "")
	if err != nil {
		return remoteImageSubject{}, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		challenge := resp.Header.Get("WWW-Authenticate")
		resp.Body.Close()
		bearerCredential, err := registryAuthorization(ctx, client, ref, challenge)
		if err != nil {
			return remoteImageSubject{}, err
		}
		resp, err = manifestRequest(ctx, client, ref, bearerCredential)
		if err != nil {
			return remoteImageSubject{}, err
		}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return remoteImageSubject{}, fmt.Errorf("registry manifest: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	manifest, err := io.ReadAll(io.LimitReader(resp.Body, (16<<20)+1))
	if err != nil {
		return remoteImageSubject{}, err
	}
	if len(manifest) > 16<<20 {
		return remoteImageSubject{}, fmt.Errorf("container manifest exceeds 16 MiB")
	}
	d := sha256.Sum256(manifest)
	digest := "sha256:" + hex.EncodeToString(d[:])
	if header := resp.Header.Get("Docker-Content-Digest"); header != "" && header != digest {
		return remoteImageSubject{}, fmt.Errorf("registry digest header mismatch: %s != %s", header, digest)
	}
	if digestPattern.MatchString(ref.Identifier) && ref.Identifier != digest {
		return remoteImageSubject{}, fmt.Errorf("requested digest mismatch: %s != %s", ref.Identifier, digest)
	}
	mediaType := strings.TrimSpace(strings.Split(resp.Header.Get("Content-Type"), ";")[0])
	if mediaType == "" {
		return remoteImageSubject{}, fmt.Errorf("registry response has no manifest media type")
	}
	switch mediaType {
	case "application/vnd.oci.image.index.v1+json", "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json", "application/vnd.docker.distribution.manifest.v2+json":
	default:
		return remoteImageSubject{}, fmt.Errorf("unsupported container manifest media type %q", mediaType)
	}
	var envelope struct {
		MediaType string `json:"mediaType"`
	}
	if err := json.Unmarshal(manifest, &envelope); err != nil {
		return remoteImageSubject{}, fmt.Errorf("invalid container manifest JSON: %w", err)
	}
	if envelope.MediaType != "" && envelope.MediaType != mediaType {
		return remoteImageSubject{}, fmt.Errorf("manifest mediaType mismatch: body %q, header %q", envelope.MediaType, mediaType)
	}
	return remoteImageSubject{Format: "sugyeol-container-image", Version: 1, Reference: input,
		ResolvedReference: ref.Registry + "/" + ref.Repository + "@" + digest, Registry: ref.Registry, Repository: ref.Repository,
		Digest: digest, MediaType: mediaType, ManifestSize: int64(len(manifest)), ManifestSHA256: hex.EncodeToString(d[:])}, nil
}

func manifestRequest(ctx context.Context, client *http.Client, ref parsedImageReference, authorization string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ref.endpoint(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", manifestAccept)
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", "sugyeol-container-signing")
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	return client.Do(req)
}

func registryAuthorization(ctx context.Context, client *http.Client, ref parsedImageReference, challenge string) (string, error) {
	cred := dockerCredential(ref.Registry)
	if strings.HasPrefix(strings.ToLower(challenge), "basic") {
		if cred.Username == "" {
			return "", fmt.Errorf("registry requires basic authentication; run docker login %s", ref.Registry)
		}
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(cred.Username+":"+cred.Password)), nil
	}
	if !strings.HasPrefix(strings.ToLower(challenge), "bearer") {
		return "", fmt.Errorf("unsupported registry authentication challenge %q", challenge)
	}
	fields := map[string]string{}
	for _, match := range challengeFieldPattern.FindAllStringSubmatch(challenge, -1) {
		fields[strings.ToLower(match[1])] = match[2]
	}
	realm, err := url.Parse(fields["realm"])
	if err != nil || realm.Host == "" {
		return "", fmt.Errorf("invalid registry token realm")
	}
	host := realm.Hostname()
	if realm.Scheme != "https" && host != "localhost" && !(net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()) {
		return "", fmt.Errorf("refusing insecure registry token realm %s", realm.String())
	}
	query := realm.Query()
	if fields["service"] != "" {
		query.Set("service", fields["service"])
	}
	scope := fields["scope"]
	if scope == "" {
		scope = "repository:" + ref.Repository + ":pull"
	}
	query.Set("scope", scope)
	realm.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, realm.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "sugyeol-container-signing")
	if cred.Username != "" {
		req.SetBasicAuth(cred.Username, cred.Password)
	} else if cred.IdentityToken != "" {
		req.Header.Set("Authorization", "Bearer "+cred.IdentityToken)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("registry token service: %s", resp.Status)
	}
	var tokenResponse struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tokenResponse); err != nil {
		return "", err
	}
	bearerCredential := tokenResponse.Token
	if bearerCredential == "" {
		bearerCredential = tokenResponse.AccessToken
	}
	if bearerCredential == "" {
		return "", fmt.Errorf("registry token service returned no token")
	}
	return "Bearer " + bearerCredential, nil
}
