// Fix for syft #4708
// Only parse debian/copyright files as machine-readable if they have Format: header.
// Otherwise, only extract per-line patterns (License:, common-licenses paths, license agreement headings).
// Machine-readable files should still use the state machine for multi-line license headings.

const (
	expectHeading = iota
	expectDashes
	skipBlanks
	captureLicense
	headingDone // matched or impossible -- stop checking
)

// parseLicensesFromCopyright parses copyright file content.
// If the file starts with "Format:" (machine-readable format per Debian spec),
// all parsing including the state machine is applied.
// If no Format: is found, only per-line patterns are matched:
//   - License: fields
//   - /usr/share/common-licenses/ paths
//   - License agreement headings
// This prevents false positives from non-machine-readable copyright files.
func parseLicensesFromCopyright(reader io.Reader) []string {
	findings := strset.New()
	scanner := bufio.NewScanner(reader)

	// Detect machine-readable format by looking for Format: as the first non-empty line
	isMachineReadable := false
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "Format:") {
			isMachineReadable = true
		}
		break
	}

	// If not machine-readable, reset scanner and only apply per-line checks
	if !isMachineReadable {
		scanner = bufio.NewScanner(reader)
		for scanner.Scan() {
			line := scanner.Text()
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
		results := findings.List()
		sort.Strings(results)
		return results
	}

	// Machine-readable format: apply full parsing including state machine
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