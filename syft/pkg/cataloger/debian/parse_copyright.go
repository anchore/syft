package debian

import (
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/internal"
)

// For more information see: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/#license-syntax

var (
	licensePattern                          = regexp.MustCompile(`^License: (?P<license>\S*)`)
	commonLicensePathPattern                = regexp.MustCompile(`/usr/share/common-licenses/(?P<license>[0-9A-Za-z_.\-]+)`)
	licenseFirstSentenceAfterHeadingPattern = regexp.MustCompile(`(?is)^[^\n]+?\n[-]+?\n+(?P<license>.*?\.)`)
	licenseAgreementHeadingPattern          = regexp.MustCompile(`(?i)^\s*(?P<license>LICENSE AGREEMENT(?: FOR .+?)?)\s*$`)
)

func parseLicensesFromCopyright(reader io.Reader) []string {
	findings := strset.New()
	data, err := io.ReadAll(reader)
	if err != nil {
		// Fail-safe: return nothing if unable to read
		return []string{}
	}

	content := string(data)
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if value := findLicenseClause(licensePattern, line); value != "" {
			findings.Add(value)
		}
		if value := findLicenseClause(commonLicensePathPattern, line); value != "" {
			findings.Add(value)
		}
		if value := findLicenseClause(licenseAgreementHeadingPattern, line); value != "" {
			findings.Add(value)
		}
	}

	// some copyright files have a license declaration after the heading ex:
	// End User License Agreement\n--------------------------
	// we want to try and find these multi-line license declarations and make exceptions for them
	if value := findLicenseClause(licenseFirstSentenceAfterHeadingPattern, content); value != "" {
		findings.Add(value)
	}

	results := findings.List()
	sort.Strings(results)

	return results
}

func findLicenseClause(pattern *regexp.Regexp, line string) string {
	valueGroup := "license"
	matchesByGroup := internal.MatchNamedCaptureGroups(pattern, line)

	candidate, ok := matchesByGroup[valueGroup]
	if !ok {
		return ""
	}

	return ensureIsSingleLicense(candidate)
}

var multiLicenseExceptions = []string{
	"NVIDIA Software License Agreement",
}

func ensureIsSingleLicense(candidate string) (license string) {
	candidate = strings.TrimSpace(strings.ReplaceAll(candidate, "\n", " "))

	// Check for exceptions first
	for _, exception := range multiLicenseExceptions {
		if strings.Contains(candidate, exception) {
			return strings.TrimSuffix(candidate, ".")
		}
	}
	if strings.Contains(candidate, " or ") || strings.Contains(candidate, " and ") {
		// make sure this is not one of the license exceptions
		// this is a multi-license summary, ignore this as other recurrent license lines should cover this
		return
	}
	if candidate != "" && strings.ToLower(candidate) != "none" {
		// the license may be at the end of a sentence, clean . characters
		license = strings.TrimSuffix(candidate, ".")
	}
	return license
}
