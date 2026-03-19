package bun

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

type bunPackage struct {
	Name         string
	Version      string
	Resolved     string
	Integrity    string
	Dependencies map[string]string
}

var (
	bunLockHeader = regexp.MustCompile(`^//\s*bun\.?lock`)
)

func parseBunLock(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	if pathContainsNodeModulesDirectory(reader.Path()) {
		return nil, nil, nil
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("read bun.lock: %w", err)
	}

	if !isBunLockFile(data) {
		return nil, nil, nil
	}

	jsonData := removeJSONCComments(data)

	bunPkgs, err := parseBunLockJSON(jsonData)
	if err != nil {
		return nil, nil, fmt.Errorf("parse bun.lock: %w", err)
	}

	var packages []pkg.Package
	for _, p := range bunPkgs {
		packages = append(packages, newBunLockPackage(reader.Location, p))
	}

	return packages, nil, unknown.IfEmptyf(packages, "no pkgs in bun.lock")
}

func isBunLockFile(data []byte) bool {
	lines := strings.SplitN(string(data), "\n", 5)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if bunLockHeader.MatchString(line) {
			return true
		}
		if strings.HasPrefix(line, "{") {
			return true
		}
	}
	return false
}

func removeJSONCComments(data []byte) []byte {
	var result strings.Builder
	content := string(data)
	inString := false
	inSingleComment := false
	inMultiComment := false

	for i := 0; i < len(content); i++ {
		c := content[i]

		if inSingleComment {
			if c == '\n' {
				inSingleComment = false
				result.WriteByte(c)
			}
			continue
		}

		if inMultiComment {
			if c == '*' && i+1 < len(content) && content[i+1] == '/' {
				inMultiComment = false
				i++ // skip the '/'
			}
			continue
		}

		if c == '"' && (i == 0 || content[i-1] != '\\') {
			inString = !inString
		}

		if !inString {
			if c == '/' && i+1 < len(content) {
				next := content[i+1]
				if next == '/' {
					inSingleComment = true
					continue
				}
				if next == '*' {
					inMultiComment = true
					i++ // skip the '*'
					continue
				}
			}
		}

		result.WriteByte(c)
	}

	return []byte(result.String())
}

// bun.lock format: "packages" map with [resolved, {deps}, integrity] arrays
func parseBunLockJSON(data []byte) ([]bunPackage, error) {
	var lockfile map[string]any
	if err := json.Unmarshal(data, &lockfile); err != nil {
		return nil, fmt.Errorf("unmarshal bun.lock: %w", err)
	}

	var packages []bunPackage

	if pkgs, ok := lockfile["packages"].(map[string]any); ok {
		for key, value := range pkgs {
			pkg := parseBunPackageEntry(key, value)
			if pkg != nil {
				packages = append(packages, *pkg)
			}
		}
	}

	return packages, nil
}

// array format: [resolved-url, {deps}, integrity] or key-only name@ver
func parseBunPackageEntry(key string, value any) *bunPackage {
	if arr, ok := value.([]any); ok && len(arr) >= 1 {
		return parseBunPackageArray(key, arr)
	}

	// fallback: parse name@ver from key
	name, version := parsePackageKey(key)
	if name != "" && version != "" {
		return &bunPackage{
			Name:    name,
			Version: version,
		}
	}

	return nil
}

func parseBunPackageArray(key string, arr []any) *bunPackage {
	if len(arr) < 1 {
		return nil
	}

	var name, version, resolved, integrity string
	dependencies := make(map[string]string)

	name, version = parsePackageKey(key)

	for i, elem := range arr {
		switch v := elem.(type) {
		case string:
			switch {
			case strings.HasPrefix(v, "http") || strings.Contains(v, "://"):
				resolved = v
			case strings.HasPrefix(v, "sha"):
				integrity = v
			case i == 0 && name == "":
				name, version = parsePackageKey(v)
			}
		case map[string]any:
			for depName, depVer := range v {
				if verStr, ok := depVer.(string); ok {
					dependencies[depName] = verStr
				}
			}
		}
	}

	if name == "" {
		return nil
	}

	return &bunPackage{
		Name:         name,
		Version:      version,
		Resolved:     resolved,
		Integrity:    integrity,
		Dependencies: dependencies,
	}
}

// parsePackageKey splits "name@ver" or "@scope/name@ver"
func parsePackageKey(key string) (name, version string) {
	// Handle scoped packages (@scope/name@version)
	if strings.HasPrefix(key, "@") {
		scope, rest, found := strings.Cut(key, "/")
		if !found {
			return key, ""
		}
		atIndex := strings.LastIndex(rest, "@")
		if atIndex == -1 {
			return key, ""
		}
		return scope + "/" + rest[:atIndex], rest[atIndex+1:]
	}

	// Non-scoped packages (name@version)
	atIndex := strings.LastIndex(key, "@")
	if atIndex == -1 || atIndex == 0 {
		return key, ""
	}

	return key[:atIndex], key[atIndex+1:]
}

func pathContainsNodeModulesDirectory(p string) bool {
	return strings.Contains(p, "node_modules")
}
