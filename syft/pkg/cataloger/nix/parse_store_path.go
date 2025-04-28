package nix

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

var (
	numericPattern = regexp.MustCompile(`\d`)

	// attempts to find the right-most example of something that appears to be a version (semver or otherwise)
	// example input: h0cnbmfcn93xm5dg2x27ixhag1cwndga-glibc-2.34-210-bin
	// example output:
	//  version: "2.34-210"
	//  major: "2"
	//  minor: "34"
	//  patch: "210"
	// (there are other capture groups, but they can be ignored)
	rightMostVersionIshPattern = regexp.MustCompile(`-(?P<version>(?P<major>[0-9][a-zA-Z0-9]*)(\.(?P<minor>[0-9][a-zA-Z0-9]*))?(\.(?P<patch>0|[1-9][a-zA-Z0-9]*)){0,3}(?:-(?P<prerelease>\d*[.0-9a-zA-Z-]*)*)?(?:\+(?P<metadata>[.0-9a-zA-Z-]+(?:\.[.0-9a-zA-Z-]+)*))?)`)

	unstableVersion = regexp.MustCompile(`-(?P<version>unstable-\d{4}-\d{2}-\d{2})$`)
)

// checkout the package naming conventions here: https://nixos.org/manual/nixpkgs/stable/#sec-package-naming

type nixStorePath struct {
	StorePath  string
	OutputHash string
	Name       string
	Version    string
	Output     string
}

func (p nixStorePath) isValidPackage() bool {
	return p.Name != "" && p.Version != ""
}

func findParentNixStorePath(source string) string {
	source = strings.TrimRight(source, "/")
	indicator := "nix/store/"
	start := strings.Index(source, indicator)
	if start == -1 {
		return ""
	}

	startOfHash := start + len(indicator)
	nextField := strings.Index(source[startOfHash:], "/")
	if nextField == -1 {
		return ""
	}
	startOfSubPath := startOfHash + nextField

	return source[0:startOfSubPath]
}

func parseNixStorePath(og string) *nixStorePath {
	if strings.HasSuffix(og, ".drv") {
		// ignore derivations
		return nil
	}

	source := path.Base(og)

	versionStartIdx, versionIsh, prerelease := findVersionIsh(source)
	if versionStartIdx == -1 {
		return nil
	}

	hashName := strings.TrimSuffix(source[0:versionStartIdx], "-")
	hashNameFields := strings.Split(hashName, "-")
	if len(hashNameFields) < 2 {
		return nil
	}
	hash, name := hashNameFields[0], strings.Join(hashNameFields[1:], "-")

	prereleaseFields := strings.Split(prerelease, "-")
	lastPrereleaseField := prereleaseFields[len(prereleaseFields)-1]

	var version = versionIsh
	var output string
	if !hasNumeric(lastPrereleaseField) {
		// this last prerelease field is probably a nix output
		version = strings.TrimSuffix(versionIsh, fmt.Sprintf("-%s", lastPrereleaseField))
		output = lastPrereleaseField
	}

	if og != "" && !strings.HasPrefix(og, "/") {
		og = fmt.Sprintf("/%s", og)
	}

	return &nixStorePath{
		StorePath:  og,
		OutputHash: hash,
		Name:       name,
		Version:    version,
		Output:     output,
	}
}

func hasNumeric(s string) bool {
	return numericPattern.MatchString(s)
}

func findVersionIsh(input string) (int, string, string) {
	// we want to return the index of the start of the "version" group (the first capture group).
	// note that the match indices are in the form of [start, end, start, end, ...]. Also note that the
	// capture group for version in both regexes are the same index, but if the regexes are changed
	// this code will start to fail.

	// check for unstable version pattern first
	if match := unstableVersion.FindStringSubmatch(input); match != nil {
		indices := unstableVersion.FindStringSubmatchIndex(input)
		versionStart := indices[2] // index of first capture group's start
		version := match[1]        // first capture group is the version
		return versionStart, version, ""
	}

	// try the regular version pattern
	match := rightMostVersionIshPattern.FindStringSubmatch(input)
	if match == nil {
		return -1, "", ""
	}

	version := match[1] // capture group 1 is the version
	indices := rightMostVersionIshPattern.FindStringSubmatchIndex(input)
	versionStart := indices[2] // index of first capture group's start
	prerelease := match[7]     // capture group 7 is the prerelease version

	return versionStart, version, prerelease
}
