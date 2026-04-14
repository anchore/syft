package debian

import (
	"bufio"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/internal"
)

// For more information see: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/#license-syntax

var (
	licensePattern                 = regexp.MustCompile(`^License: (?P<license>\S*)`)
	commonLicensePathPattern       = regexp.MustCompile(`/usr/share/common-licenses/(?P<license>[0-9A-Za-z_.\-]+)`)
	licenseAgreementHeadingPattern = regexp.MustCompile(`(?i)^\s*(?P<license>LICENSE AGREEMENT(?: FOR .+?)?)\s*$`)
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
