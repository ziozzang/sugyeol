package main

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
)

type unpackPackage struct {
	setID string
	paths []string
}

// resolveUnpackPackages accepts package prefixes, literal ZIP paths, and quoted
// glob patterns. Parts are grouped by their signed package set ID, so shell-
// expanded part lists and multiple package prefixes work in the same command.
func resolveUnpackPackages(selectors []string) ([]unpackPackage, error) {
	var paths []string
	seenPaths := make(map[string]bool)
	for _, selector := range selectors {
		matches, err := resolveUnpackSelector(selector)
		if err != nil {
			return nil, err
		}
		if len(matches) == 0 {
			return nil, fmt.Errorf(tr("unpack_no_match"), selector)
		}
		for _, path := range matches {
			absolute, err := filepath.Abs(path)
			if err != nil {
				return nil, err
			}
			if seenPaths[absolute] {
				continue
			}
			seenPaths[absolute] = true
			paths = append(paths, path)
		}
	}

	groups := make(map[string]*unpackPackage)
	order := make([]string, 0)
	for _, path := range paths {
		setID, err := readPackageSetID(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		group := groups[setID]
		if group == nil {
			group = &unpackPackage{setID: setID}
			groups[setID] = group
			order = append(order, setID)
		}
		group.paths = append(group.paths, path)
	}

	result := make([]unpackPackage, 0, len(order))
	for _, setID := range order {
		group := groups[setID]
		sort.Strings(group.paths)
		result = append(result, *group)
	}
	return result, nil
}

func resolveUnpackSelector(selector string) ([]string, error) {
	// A directory selector intentionally restores every package found directly
	// in that directory. In particular, `sugyeol unpack .` is a convenient way
	// to restore all package sets in the current working directory.
	if info, err := os.Stat(selector); err == nil && info.IsDir() {
		return regularZIPFiles(globZIPDirectory(selector)), nil
	}
	if strings.ContainsAny(selector, "*?[") {
		matches, err := filepath.Glob(selector)
		if err != nil {
			return nil, fmt.Errorf("invalid unpack pattern %q: %w", selector, err)
		}
		return regularZIPFiles(matches), nil
	}
	if info, err := os.Stat(selector); err == nil && info.Mode().IsRegular() && strings.EqualFold(filepath.Ext(selector), ".zip") {
		return []string{selector}, nil
	}
	var matches []string
	for _, pattern := range []string{selector + "_part-*.zip", selector + ".part-*.zip"} {
		found, err := filepath.Glob(pattern)
		if err != nil {
			return nil, err
		}
		matches = append(matches, found...)
	}
	matches = regularZIPFiles(matches)
	if len(matches) > 0 {
		return matches, nil
	}

	// Finally treat the basename as a case-insensitive fragment of a part
	// filename. Every matching signed package set is selected.
	dir, fragment := filepath.Split(filepath.Clean(selector))
	if dir == "" {
		dir = "."
	}
	fragment = strings.ToLower(fragment)
	normalizedFragment := normalizePartFragment(fragment)
	packageHint := normalizedFragment
	if index := strings.Index(packageHint, "part"); index >= 0 {
		packageHint = packageHint[:index]
	}
	var candidates []string
	for _, path := range globZIPDirectory(dir) {
		base := strings.ToLower(filepath.Base(path))
		normalizedBase := normalizePartFragment(base)
		if strings.Contains(base, fragment) || normalizedFragment != "" && strings.Contains(normalizedBase, normalizedFragment) || packageHint != "" && strings.HasPrefix(normalizedBase, packageHint+"part") {
			candidates = append(candidates, path)
		}
	}
	candidates = regularZIPFiles(candidates)
	if len(candidates) == 0 {
		return nil, nil
	}
	return expandPackageSiblings(candidates), nil
}

func normalizePartFragment(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsNumber(r) {
			return unicode.ToLower(r)
		}
		return -1
	}, value)
}

func globZIPDirectory(dir string) []string {
	matches, _ := filepath.Glob(filepath.Join(dir, "*.zip"))
	return matches
}

// expandPackageSiblings turns a single matching part into the complete signed
// package set. Unrelated or malformed ZIP files in the directory are ignored.
func expandPackageSiblings(seeds []string) []string {
	wanted := make(map[string]bool)
	dirs := make(map[string]bool)
	for _, seed := range seeds {
		if setID, err := readPackageSetID(seed); err == nil {
			wanted[setID] = true
			dirs[filepath.Dir(seed)] = true
		}
	}
	if len(wanted) == 0 {
		return seeds
	}
	var result []string
	for dir := range dirs {
		for _, path := range regularZIPFiles(globZIPDirectory(dir)) {
			if setID, err := readPackageSetID(path); err == nil && wanted[setID] {
				result = append(result, path)
			}
		}
	}
	sort.Strings(result)
	return result
}

func regularZIPFiles(paths []string) []string {
	result := make([]string, 0, len(paths))
	for _, path := range paths {
		info, err := os.Stat(path)
		if err == nil && info.Mode().IsRegular() && strings.EqualFold(filepath.Ext(path), ".zip") {
			result = append(result, path)
		}
	}
	return result
}

func readPackageSetID(path string) (string, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return "", fmt.Errorf("ZIP open: %w", err)
	}
	defer zr.Close()
	var manifestFile *zip.File
	for _, file := range zr.File {
		if file.Name == "manifest.json" {
			if manifestFile != nil {
				return "", fmt.Errorf("duplicate manifest.json")
			}
			manifestFile = file
		}
	}
	manifestBytes, err := readSmall(manifestFile, 64*1024)
	if err != nil {
		return "", fmt.Errorf("manifest: %w", err)
	}
	var m manifest
	if err := json.Unmarshal(manifestBytes, &m); err != nil {
		return "", fmt.Errorf("manifest JSON: %w", err)
	}
	if strings.TrimSpace(m.SetID) == "" {
		return "", fmt.Errorf("manifest has no package set ID")
	}
	return m.SetID, nil
}
