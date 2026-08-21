package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const updateRepo = "ziozzang/sugyeol"
const updateCheckInterval = 24 * time.Hour

func updateCommand(args []string) error {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	check := fs.Bool("check", false, "only check for a newer release")
	force := fs.Bool("force", false, "reinstall even when already current")
	target := fs.String("version", "", "install a specific release tag")
	fs.BoolVar(check, "c", false, "only check for a newer release")
	fs.BoolVar(force, "f", false, "reinstall even when already current")
	fs.StringVar(target, "v", "", "install a specific release tag")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	client := &http.Client{}
	rel, err := fetchRelease(ctx, client, updateRepo, *target, os.Getenv("GITHUB_TOKEN"))
	if err != nil {
		return fmt.Errorf("release lookup: %w", err)
	}
	latest := rel.Version()
	cmp := compareVersions(latest, version)
	fmt.Printf(tr("update_current"), version, latest)
	if cmp > 0 {
		fmt.Printf(tr("update_available"), version, latest)
	} else if cmp == 0 {
		fmt.Print(tr("update_latest"))
	} else {
		fmt.Printf(tr("update_newer"), latest)
	}
	if *check || (cmp <= 0 && *target == "" && !*force) {
		return nil
	}
	assetName, err := releaseAssetName(latest, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return err
	}
	a, ok := rel.findAsset(assetName)
	if !ok {
		return fmt.Errorf("release %s has no asset %s", rel.TagName, assetName)
	}
	sums, err := releaseChecksums(ctx, client, rel)
	if err != nil {
		return err
	}
	want := sums[assetName]
	if want == "" {
		return fmt.Errorf("SHA256SUMS has no checksum for %s", assetName)
	}
	exe, err := resolveExecutable()
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, tr("update_downloading"), assetName, humanSize(a.Size))
	tmp, err := downloadVerified(ctx, client, a, want, filepath.Dir(exe))
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return fmt.Errorf("cannot update %s without write permission: %w", exe, err)
		}
		return err
	}
	if err := replaceExecutable(exe, tmp); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	fmt.Printf(tr("updated"), exe, version, latest)
	if notes := strings.TrimSpace(rel.Body); notes != "" {
		fmt.Printf("\n--- %s ---\n%s\n", rel.TagName, notes)
	}
	return nil
}

type updateCache struct {
	CheckedAt time.Time `json:"checked_at"`
	Latest    string    `json:"latest_version"`
}

func updateEligible(args []string) bool {
	if os.Getenv("SUGYEOL_NO_UPDATE_CHECK") != "" {
		return false
	}
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "update", "self-update", "version", "--version", "-version", "help", "-h", "--help":
		return false
	}
	info, err := os.Stderr.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func startUpdateRefresh(args []string) {
	if !updateEligible(args) {
		return
	}
	path := updateCachePath()
	c := readUpdateCache(path)
	if c.Latest != "" && time.Since(c.CheckedAt) < updateCheckInterval {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		rel, err := fetchRelease(ctx, &http.Client{}, updateRepo, "", os.Getenv("GITHUB_TOKEN"))
		if err == nil {
			writeUpdateCache(path, updateCache{CheckedAt: time.Now(), Latest: rel.Version()})
		}
	}()
}

func maybeNotifyUpdate(args []string) {
	if !updateEligible(args) {
		return
	}
	c := readUpdateCache(updateCachePath())
	if compareVersions(c.Latest, version) > 0 {
		fmt.Fprintf(os.Stderr, "\n%s\n", tr("update_notice", c.Latest, version))
	}
}

func updateCachePath() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "sugyeol", "update-check.json")
}
func readUpdateCache(path string) updateCache {
	var c updateCache
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &c)
	}
	return c
}
func writeUpdateCache(path string, c updateCache) {
	if os.MkdirAll(filepath.Dir(path), 0755) != nil {
		return
	}
	b, err := json.Marshal(c)
	if err != nil {
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".update-check-*")
	if err != nil {
		return
	}
	name := tmp.Name()
	ok := false
	defer func() {
		tmp.Close()
		if !ok {
			os.Remove(name)
		}
	}()
	if _, err = tmp.Write(b); err != nil {
		return
	}
	if err = tmp.Close(); err != nil {
		return
	}
	if err = os.Rename(name, path); err == nil {
		ok = true
	}
}

func humanSize(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	units := []string{"KiB", "MiB", "GiB", "TiB"}
	v := float64(n)
	for _, u := range units {
		v /= 1024
		if v < 1024 {
			return fmt.Sprintf("%.1f %s", v, u)
		}
	}
	return fmt.Sprintf("%.1f PiB", v/1024)
}
