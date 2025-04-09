package nix

import (
	"regexp"
	"strings"
)

type nixStorePath struct {
	path       string
	hash       string
	outputHash string
	name       string
	version    string
	output     string
	// New field to indicate the type of Nix path
	pathType string // "package", "derivation", "source", or "other"
}

// parseNixStorePath extracts package information from a Nix store path.
// This is a more permissive implementation that accepts more formats.
func parseNixStorePath(path string) *nixStorePath {
	// Extract the store path component - handle both standard and short forms
	// Standard form: /nix/store/[hash]-[name]
	// Short form: /[hash]-[name]
	storePathPattern := regexp.MustCompile(`(^|.*?)(?:/nix/store/|/)([a-z0-9]{32})-(.+?)(/.*)?$`)
	matches := storePathPattern.FindStringSubmatch(path)
	if len(matches) < 4 {
		return nil
	}

	// Extract hash and full package name
	hash := matches[2]
	fullName := matches[3]

	// Extract path to first / after the hash-name pattern
	basePath := "/nix/store/" + hash + "-" + fullName
	if len(matches) > 4 && matches[4] != "" {
		// We have a file within a store path
		basePath = "/nix/store/" + hash + "-" + fullName
	}

	// Create the basic result
	result := &nixStorePath{
		path:       basePath,
		hash:       hash,
		outputHash: hash,
	}

	// Determine the path type based on extension or patterns
	if strings.HasSuffix(fullName, ".drv") {
		result.pathType = "derivation"
		// Remove .drv suffix for name parsing
		fullName = strings.TrimSuffix(fullName, ".drv")
	} else if strings.Contains(fullName, ".tar.") ||
		strings.HasSuffix(fullName, ".tgz") ||
		strings.HasSuffix(fullName, ".tar.gz") ||
		strings.HasSuffix(fullName, ".tar.bz2") ||
		strings.HasSuffix(fullName, ".tar.xz") ||
		strings.HasSuffix(fullName, ".zip") ||
		strings.HasSuffix(fullName, ".patch") {
		result.pathType = "source"
	} else {
		result.pathType = "package"
	}

	// Try to parse the output from the path (if present)
	if outputParts := strings.Split(fullName, "-"); len(outputParts) > 1 {
		lastPart := outputParts[len(outputParts)-1]
		// Common Nix output names
		outputs := map[string]bool{
			"bin": true, "dev": true, "lib": true, "man": true,
			"doc": true, "info": true, "out": true,
		}
		if outputs[lastPart] {
			result.output = lastPart
			fullName = strings.Join(outputParts[:len(outputParts)-1], "-")
		}
	}

	// For non-drv files, try different version extraction patterns
	versionPatterns := []*regexp.Regexp{
		// Standard version: name-1.2.3
		regexp.MustCompile(`^(.+)-([0-9][0-9.]+(?:-[0-9]+)?)$`),

		// Unstable version: name-unstable-2022-05-15
		regexp.MustCompile(`^(.+)-unstable-([0-9]{4}-[0-9]{2}-[0-9]{2})$`),

		// Version with prefix: name-v1.2.3
		regexp.MustCompile(`^(.+)-(v[0-9][0-9.]+)$`),

		// Year-based versions: name-2022.05
		regexp.MustCompile(`^(.+)-([0-9]{4}(?:\.[0-9]+)*)$`),

		// Version with suffix: name-1.2.3-suffix
		regexp.MustCompile(`^(.+)-([0-9][0-9.]+(?:-[a-z0-9]+)*)$`),
	}

	// Try each pattern to extract name and version
	for _, pattern := range versionPatterns {
		if nameVerMatches := pattern.FindStringSubmatch(fullName); len(nameVerMatches) == 3 {
			result.name = nameVerMatches[1]
			result.version = nameVerMatches[2]
			return result
		}
	}

	// If no version pattern matched, consider the entire string the package name
	result.name = fullName
	result.version = ""

	return result
}

// isLikelyOutput checks if a string is likely to be a Nix output name
func isLikelyOutput(s string) bool {
	commonOutputs := map[string]bool{
		"bin": true, "lib": true, "dev": true, "out": true,
		"doc": true, "man": true, "info": true, "devdoc": true,
	}
	return commonOutputs[s]
}

// isLikelyVersion checks if a string looks like a version number
func isLikelyVersion(s string) bool {
	// Simple check for common version patterns
	versionPattern := regexp.MustCompile(`^v?\d+(\.\d+)*(-\w+)*$`)
	return versionPattern.MatchString(s)
}

// shouldIncludeAsPackage determines if this store path should be included as a package
func (n *nixStorePath) shouldIncludeAsPackage() bool {
	// Only include actual packages, not derivations or source files
	if n.pathType == "derivation" || n.pathType == "source" {
		return false
	}

	// Skip paths that look like source archives even if not explicitly marked
	if strings.HasSuffix(n.path, ".tar.gz") ||
		strings.HasSuffix(n.path, ".tgz") ||
		strings.HasSuffix(n.path, ".tar.bz2") ||
		strings.HasSuffix(n.path, ".tar.xz") ||
		strings.HasSuffix(n.path, ".zip") ||
		strings.HasSuffix(n.path, ".drv") {
		return false
	}

	// Make sure it has a name (at minimum)
	return n.name != ""
}

// isValidPackage should be much more permissive
func (n *nixStorePath) isValidPackage() bool {
	// Any path with a hash and name is considered valid
	return n.hash != "" && n.name != ""
}
