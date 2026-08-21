package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

const githubAPI = "https://api.github.com"

type release struct {
	TagName string  `json:"tag_name"`
	Body    string  `json:"body"`
	Assets  []asset `json:"assets"`
}

type asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}

func (r *release) Version() string { return strings.TrimPrefix(r.TagName, "v") }
func (r *release) findAsset(name string) (asset, bool) {
	for _, a := range r.Assets {
		if a.Name == name {
			return a, true
		}
	}
	return asset{}, false
}

func fetchRelease(ctx context.Context, client *http.Client, repo, tag, token string) (*release, error) {
	endpoint := githubAPI + "/repos/" + repo + "/releases/latest"
	if tag != "" {
		endpoint = githubAPI + "/repos/" + repo + "/releases/tags/" + tag
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "packer-selfupdate")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("GitHub API %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var rel release
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&rel); err != nil {
		return nil, err
	}
	if rel.TagName == "" {
		return nil, fmt.Errorf("release has no tag")
	}
	return &rel, nil
}

func releaseAssetName(ver, goos, goarch string) (string, error) {
	platform := map[string]string{"darwin": "macos", "windows": "windows", "linux": "linux"}[goos]
	arch := map[string]string{"amd64": "x86_64", "arm64": "arm64"}[goarch]
	if platform == "" || arch == "" {
		return "", fmt.Errorf("no release build for %s/%s", goos, goarch)
	}
	name := fmt.Sprintf("packer_%s_%s_%s", ver, platform, arch)
	if goos == "windows" {
		name += ".exe"
	}
	return name, nil
}

func compareVersions(a, b string) int {
	af, bf := versionFields(a), versionFields(b)
	for i := 0; i < len(af) || i < len(bf); i++ {
		var x, y int
		if i < len(af) {
			x = af[i]
		}
		if i < len(bf) {
			y = bf[i]
		}
		if x < y {
			return -1
		}
		if x > y {
			return 1
		}
	}
	return 0
}

func versionFields(v string) []int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	out := make([]int, len(parts))
	for i, p := range parts {
		out[i], _ = strconv.Atoi(p)
	}
	return out
}

func releaseChecksums(ctx context.Context, client *http.Client, rel *release) (map[string]string, error) {
	a, ok := rel.findAsset("SHA256SUMS")
	if !ok {
		return nil, fmt.Errorf("release %s has no SHA256SUMS", rel.TagName)
	}
	b, err := downloadBytes(ctx, client, a.URL, 1<<20)
	if err != nil {
		return nil, err
	}
	result := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && len(fields[0]) == 64 {
			result[fields[1]] = strings.ToLower(fields[0])
		}
	}
	return result, nil
}

func downloadBytes(ctx context.Context, client *http.Client, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "packer-selfupdate")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download: %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

func downloadVerified(ctx context.Context, client *http.Client, a asset, want, dir string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.URL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "packer-selfupdate")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download %s: %s", a.Name, resp.Status)
	}
	tmp, err := os.CreateTemp(dir, ".packer-update-*")
	if err != nil {
		return "", err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		tmp.Close()
		if !ok {
			os.Remove(name)
		}
	}()
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), resp.Body); err != nil {
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, want) {
		return "", fmt.Errorf("checksum mismatch for %s: got %s, want %s", a.Name, got, want)
	}
	if err := os.Chmod(name, 0755); err != nil {
		return "", err
	}
	ok = true
	return name, nil
}

func resolveExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		return resolved, nil
	}
	return exe, nil
}

func replaceExecutable(dest, src string) error {
	if runtime.GOOS != "windows" {
		return os.Rename(src, dest)
	}
	old := dest + ".old"
	_ = os.Remove(old)
	if err := os.Rename(dest, old); err != nil {
		return err
	}
	if err := os.Rename(src, dest); err != nil {
		_ = os.Rename(old, dest)
		return err
	}
	_ = os.Remove(old)
	return nil
}
