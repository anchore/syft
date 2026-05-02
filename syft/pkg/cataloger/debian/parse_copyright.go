package debian

import (
	"bufio"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/spdxlicense"
)

// For more information see: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/#license-syntax

var (
	licensePattern                 = regexp.MustCompile(`^License: (?P<license>\S*)`)
	commonLicensePathPattern       = regexp.MustCompile(`/usr/share/common-licenses/(?P<license>[0-9A-Za-z_.\-]+)`)
	licenseAgreementHeadingPattern = regexp.MustCompile(`(?i)^\s*(?P<license>LICENSE AGREEMENT(?: FOR .+?)?)\s*$`)

	// formatHeaderPattern matches the deb822 machine-readable copyright format
	// declaration (https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/).
	// The Format: header is the canonical signal that the file is structured.
	formatHeaderPattern = regexp.MustCompile(`^Format:\s*(?P<url>https?://\S+)`)

	// urlPattern matches URLs that may point at a license text. We intentionally
	// stop at common non-URL trailing punctuation (.,;:)) so that ".html.", "(URL)"
	// etc. don't pollute the lookup key.
	urlPattern = regexp.MustCompile(`https?://[^\s<>"\\)\]]+`)
)

func parseLicensesFromCopyright(reader io.Reader) []string {
	findings := strset.New()
	scanner := bufio.NewScanner(reader)

	// State machine replacing licenseFirstSentenceAfterHeadingPattern.
	// That regex only matched at the start of the file: a non-empty heading,
	// a line of dashes, blank lines, then text up to the first period.
	const (
		expectHeading = iota
		expectDashes
		skipBlanks
		captureLicense
		headingDone // matched or impossible — stop checking
	)
	headingState := expectHeading
	var licenseText strings.Builder

	for scanner.Scan() {
		line := scanner.Text()

		// per-line regex checks (applied to every line)
		if value := findLicenseClause(licensePattern, line); value != "" {
			findings.Add(value)
		}
		if value := findLicenseClause(commonLicensePathPattern, line); value != "" {
			findings.Add(value)
		}
		if value := findLicenseClause(licenseAgreementHeadingPattern, line); value != "" {
			findings.Add(value)
		}
		// resolve any URLs on the line against the SPDX seeAlso URL table so that
		// references like "License: see http://www.apache.org/licenses/LICENSE-2.0"
		// surface a concrete SPDX ID even when the short-name field is missing.
		// The Format: header itself participates in the same lookup so that any
		// future variants of the deb822 spec URL register cleanly without special-casing.
		for _, id := range licenseIDsFromURLs(line) {
			findings.Add(id)
		}

		// multi-line heading detection (only at start of file)
		switch headingState {
		case expectHeading:
			if strings.TrimSpace(line) != "" {
				headingState = expectDashes
			} else {
				headingState = headingDone
			}
		case expectDashes:
			trimmed := strings.TrimSpace(line)
			if len(trimmed) > 0 && strings.Trim(trimmed, "-") == "" {
				headingState = skipBlanks
			} else {
				headingState = headingDone
			}
		case skipBlanks:
			if strings.TrimSpace(line) != "" {
				headingState = captureLicense
				licenseText.WriteString(line)
				if value := extractUpToFirstPeriod(licenseText.String()); value != "" {
					findings.Add(value)
					headingState = headingDone
				}
			}
		case captureLicense:
			licenseText.WriteString(" ")
			licenseText.WriteString(line)
			if value := extractUpToFirstPeriod(licenseText.String()); value != "" {
				findings.Add(value)
				headingState = headingDone
			}
		}
	}

	results := findings.List()
	sort.Strings(results)

	return results
}

// extractUpToFirstPeriod returns the license text up to the first period,
// processed through ensureIsSingleLicense, or "" if no period found yet.
func extractUpToFirstPeriod(s string) string {
	if idx := strings.Index(s, "."); idx >= 0 {
		return ensureIsSingleLicense(s[:idx+1])
	}
	return ""
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

// hasMachineReadableFormat reports whether the given debian/copyright content
// declares itself in the deb822 machine-readable copyright format by exposing
// a top-level "Format:" header pointing at the spec.
//
// Per https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/ the
// Format field is mandatory and must appear in the first stanza, so the check
// only walks lines until the first blank line (stanza terminator).
func hasMachineReadableFormat(content string) bool {
	for _, line := range strings.Split(content, "\n") {
		if strings.TrimSpace(line) == "" {
			return false
		}
		if formatHeaderPattern.MatchString(line) {
			return true
		}
	}
	return false
}

// licenseIDsFromURLs returns SPDX license IDs for any URLs on the given line
// that match an entry in the SPDX seeAlso URL table.
func licenseIDsFromURLs(line string) []string {
	matches := urlPattern.FindAllString(line, -1)
	if len(matches) == 0 {
		return nil
	}
	var ids []string
	for _, raw := range matches {
		// strip common trailing punctuation that a URL would not legitimately end with
		trimmed := strings.TrimRight(raw, ".,;:")
		if info, ok := spdxlicense.LicenseByURL(trimmed); ok && info.ID != "" {
			ids = append(ids, info.ID)
		}
	}
	return ids
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
