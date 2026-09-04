package main

import (
	"bufio"
	"encoding/json"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
)

var gemLockLine = regexp.MustCompile(`^ {4}([^ ]+) \(([^)]+)\)`)

// catalogExtraSBOMFile handles lockfiles and installed-package metadata that
// are independent from the OS package database catalogers.
func catalogExtraSBOMFile(file sbomFile, add func(sbomPackage)) bool {
	lower, base := strings.ToLower(file.Path), strings.ToLower(path.Base(file.Path))
	switch {
	case base == "composer.lock":
		var lock struct {
			Packages    []composerPackage `json:"packages"`
			PackagesDev []composerPackage `json:"packages-dev"`
		}
		if json.Unmarshal(file.Data, &lock) == nil {
			for _, p := range append(lock.Packages, lock.PackagesDev...) {
				add(sbomPackage{Name: p.Name, Version: p.Version, License: strings.Join(p.License, " AND "), Type: "composer", Source: file.Path})
			}
		}
		return true
	case base == "pipfile.lock":
		var lock struct {
			Default map[string]struct{ Version string } `json:"default"`
			Develop map[string]struct{ Version string } `json:"develop"`
		}
		if json.Unmarshal(file.Data, &lock) == nil {
			for name, p := range lock.Default {
				add(sbomPackage{Name: name, Version: strings.TrimPrefix(p.Version, "=="), Type: "pypi", Source: file.Path})
			}
			for name, p := range lock.Develop {
				add(sbomPackage{Name: name, Version: strings.TrimPrefix(p.Version, "=="), Type: "pypi", Source: file.Path})
			}
		}
		return true
	case base == "poetry.lock" || base == "uv.lock":
		for _, p := range sbomTOMLPackages(string(file.Data)) {
			add(sbomPackage{Name: p["name"], Version: p["version"], Type: "pypi", Source: file.Path})
		}
		return true
	case base == "yarn.lock":
		catalogYarnLock(string(file.Data), file.Path, add)
		return true
	case base == "pnpm-lock.yaml":
		catalogPNPMLock(string(file.Data), file.Path, add)
		return true
	case base == "gemfile.lock":
		for _, line := range strings.Split(string(file.Data), "\n") {
			if match := gemLockLine.FindStringSubmatch(line); len(match) == 3 {
				add(sbomPackage{Name: match[1], Version: match[2], Type: "gem", Source: file.Path})
			}
		}
		return true
	case strings.HasSuffix(lower, ".gemspec"):
		name, version := gemspecValue(string(file.Data), ".name"), gemspecValue(string(file.Data), ".version")
		add(sbomPackage{Name: name, Version: version, Type: "gem", Source: file.Path})
		return true
	case base == "project.assets.json" || strings.HasSuffix(lower, ".deps.json"):
		var doc struct {
			Libraries map[string]json.RawMessage `json:"libraries"`
		}
		if json.Unmarshal(file.Data, &doc) == nil {
			for key := range doc.Libraries {
				name, version := splitNameVersion(key)
				add(sbomPackage{Name: name, Version: version, Type: "nuget", Source: file.Path})
			}
		}
		return true
	case base == "packages.lock.json":
		var frameworks map[string]map[string]struct {
			Resolved string `json:"resolved"`
		}
		if json.Unmarshal(file.Data, &frameworks) == nil {
			for _, packages := range frameworks {
				for name, p := range packages {
					add(sbomPackage{Name: name, Version: p.Resolved, Type: "nuget", Source: file.Path})
				}
			}
		}
		return true
	case base == "package.resolved":
		catalogSwiftResolved(file, add)
		return true
	case strings.Contains(lower, "/conda-meta/") && strings.HasSuffix(lower, ".json"):
		var p struct {
			Name, Version, License, Build string
		}
		if json.Unmarshal(file.Data, &p) == nil {
			add(sbomPackage{Name: p.Name, Version: p.Version, License: p.License, Type: "conda", Source: file.Path})
		}
		return true
	case strings.HasSuffix(lower, ".egg-info/pkg-info"):
		if paragraphs := sbomParagraphs(file.Data); len(paragraphs) > 0 {
			p := paragraphs[0]
			add(sbomPackage{Name: p["Name"], Version: p["Version"], License: p["License"], Type: "pypi", Source: file.Path})
		}
		return true
	case base == "pubspec.lock":
		catalogPubspecLock(string(file.Data), file.Path, add)
		return true
	}
	return false
}

type composerPackage struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	License []string `json:"license"`
}

func catalogYarnLock(contents, source string, add func(sbomPackage)) {
	scanner := bufio.NewScanner(strings.NewReader(contents))
	var names []string
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" && line[0] != ' ' && strings.HasSuffix(line, ":") {
			names = names[:0]
			for _, selector := range strings.Split(strings.TrimSuffix(line, ":"), ",") {
				selector = strings.Trim(strings.TrimSpace(selector), `"'`)
				if name := npmSelectorName(selector); name != "" {
					names = append(names, name)
				}
			}
			continue
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "version ") {
			version := strings.Trim(strings.TrimSpace(strings.TrimPrefix(trimmed, "version ")), `"'`)
			for _, name := range names {
				add(sbomPackage{Name: name, Version: version, Type: "npm", Source: source})
			}
		}
	}
}

func npmSelectorName(selector string) string {
	if strings.HasPrefix(selector, "@") {
		if slash := strings.IndexByte(selector, '/'); slash > 1 {
			if at := strings.IndexByte(selector[slash:], '@'); at >= 0 {
				return selector[:slash+at]
			}
		}
		return ""
	}
	if at := strings.IndexByte(selector, '@'); at > 0 {
		return selector[:at]
	}
	return selector
}

func catalogPNPMLock(contents, source string, add func(sbomPackage)) {
	for _, line := range strings.Split(contents, "\n") {
		line = strings.Trim(strings.TrimSpace(line), `"'`)
		line = strings.TrimSuffix(line, ":")
		line = strings.TrimPrefix(line, "/")
		if line == "" || strings.Contains(line, " ") || !strings.Contains(line, "@") {
			continue
		}
		at := strings.LastIndex(line, "@")
		if at <= 0 || at == len(line)-1 || strings.Contains(line[at+1:], ":") {
			continue
		}
		version := strings.SplitN(line[at+1:], "(", 2)[0]
		if version != "" && version[0] >= '0' && version[0] <= '9' {
			add(sbomPackage{Name: line[:at], Version: version, Type: "npm", Source: source})
		}
	}
}

func gemspecValue(contents, field string) string {
	for _, line := range strings.Split(contents, "\n") {
		if !strings.Contains(line, field) || !strings.Contains(line, "=") {
			continue
		}
		value := strings.TrimSpace(strings.SplitN(line, "=", 2)[1])
		value = strings.TrimPrefix(value, "Gem::Version.new(")
		value = strings.TrimSuffix(value, ")")
		return strings.Trim(value, `"'`)
	}
	return ""
}

func splitNameVersion(value string) (string, string) {
	if slash := strings.LastIndex(value, "/"); slash > 0 && slash < len(value)-1 {
		return value[:slash], value[slash+1:]
	}
	return value, ""
}

func catalogSwiftResolved(file sbomFile, add func(sbomPackage)) {
	var doc struct {
		Pins []struct {
			Identity string `json:"identity"`
			Package  string `json:"package"`
			State    struct {
				Version  string `json:"version"`
				Revision string `json:"revision"`
			} `json:"state"`
		} `json:"pins"`
		Object struct {
			Pins []struct {
				Package string `json:"package"`
				State   struct {
					Version  string `json:"version"`
					Revision string `json:"revision"`
				} `json:"state"`
			} `json:"pins"`
		} `json:"object"`
	}
	if json.Unmarshal(file.Data, &doc) != nil {
		return
	}
	for _, p := range doc.Pins {
		name := p.Identity
		if name == "" {
			name = p.Package
		}
		version := p.State.Version
		if version == "" {
			version = p.State.Revision
		}
		add(sbomPackage{Name: name, Version: version, Type: "swift", Source: file.Path})
	}
	for _, p := range doc.Object.Pins {
		version := p.State.Version
		if version == "" {
			version = p.State.Revision
		}
		add(sbomPackage{Name: p.Package, Version: version, Type: "swift", Source: file.Path})
	}
}

func catalogPubspecLock(contents, source string, add func(sbomPackage)) {
	lines := strings.Split(contents, "\n")
	for i, line := range lines {
		if !strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "    ") || !strings.HasSuffix(strings.TrimSpace(line), ":") {
			continue
		}
		name := strings.TrimSuffix(strings.TrimSpace(line), ":")
		for j := i + 1; j < len(lines) && (strings.TrimSpace(lines[j]) == "" || strings.HasPrefix(lines[j], "    ")); j++ {
			trimmed := strings.TrimSpace(lines[j])
			if strings.HasPrefix(trimmed, "version:") {
				version := strings.Trim(strings.TrimSpace(strings.TrimPrefix(trimmed, "version:")), `"'`)
				add(sbomPackage{Name: name, Version: version, Type: "pub", Source: source})
				break
			}
		}
	}
}

// Keep deterministic iteration available to callers adding future parsers.
func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func escapedPURL(kind, name, version string) string {
	purl := "pkg:" + kind + "/" + url.PathEscape(name)
	if version != "" {
		purl += "@" + url.PathEscape(version)
	}
	return purl
}
