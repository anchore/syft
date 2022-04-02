package deb

import (
	"bufio"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/anchore/syft/internal"
)

// For more information see: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/#license-syntax

var (
	licensePattern           = regexp.MustCompile(`^License: (?P<license>\S*)`)
	commonLicensePathPattern = regexp.MustCompile(`/usr/share/common-licenses/(?P<license>[0-9A-Za-z_.\-]+)`)
)

func parseLicensesFromCopyright(reader io.Reader) []string {
	findings := internal.NewStringSet()
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		line := scanner.Text()
		if value := findLicenseClause(licensePattern, "license", line); value != "" {
			findings.Add(value)
		}
		if value := findLicenseClause(commonLicensePathPattern, "license", line); value != "" {
			findings.Add(value)
		}
	}

	results := findings.ToSlice()

	sort.Strings(results)

	return results
}

func findLicenseClause(pattern *regexp.Regexp, valueGroup, line string) string {
	matchesByGroup := internal.MatchNamedCaptureGroups(pattern, line)

	candidate, ok := matchesByGroup[valueGroup]
	if !ok {
		return ""
	}

	return ensureIsSingleLicense(candidate)
}

func ensureIsSingleLicense(candidate string) (license string) {
	candidate = strings.TrimSpace(candidate)
	if strings.Contains(candidate, " or ") || strings.Contains(candidate, " and ") {
		// this is a multi-license summary, ignore this as other recurrent license lines should cover this
		return
	}
	if candidate != "" && strings.ToLower(candidate) != "none" {
		// the license may be at the end of a sentence, clean . characters
		license = strings.TrimSuffix(candidate, ".")
	}
	return license
}
