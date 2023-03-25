package nix

import (
	"fmt"
	"path"
	"strings"
)

// checkout the package naming conventions here: https://nixos.org/manual/nixpkgs/stable/#sec-package-naming

type nixStorePath struct {
	hash    string
	name    string
	version string
	output  string
}

func (p nixStorePath) isValidPackage() bool {
	return p.name != "" && p.version != ""
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

func parseNixStorePath(source string) *nixStorePath {
	if strings.HasSuffix(source, ".drv") {
		// ignore derivations
		return nil
	}

	source = path.Base(source)

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

	return &nixStorePath{
		hash:    hash,
		name:    name,
		version: version,
		output:  output,
	}
}

func hasNumeric(s string) bool {
	return numericPattern.MatchString(s)
}

func findVersionIsh(input string) (int, string, string) {
	match := rightMostVersionIshPattern.FindAllStringSubmatchIndex(input, -1)
	if len(match) == 0 || len(match[0]) == 0 {
		return -1, "", ""
	}

	// we want to return the index of the start of the "version" group (the first capture group)
	// note that the match indices are in the form of [start, end, start, end, ...]
	versionGroup := 1

	var version string
	versionStart, versionStop := match[0][versionGroup*2], match[0][(versionGroup*2)+1]
	if versionStart != -1 || versionStop != -1 {
		version = input[versionStart:versionStop]
	}

	prereleaseGroup := 7

	var prerelease string
	prereleaseStart, prereleaseStop := match[0][prereleaseGroup*2], match[0][(prereleaseGroup*2)+1]
	if prereleaseStart != -1 && prereleaseStop != -1 {
		prerelease = input[prereleaseStart:prereleaseStop]
	}

	return versionStart,
		version,
		prerelease
}
