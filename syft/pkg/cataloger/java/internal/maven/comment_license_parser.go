package maven

import (
	"context"
	"regexp"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/licenses"
)

var xmlCommentPattern = regexp.MustCompile(`(?s)<!--(.*?)-->`)

// ExtractLicensesFromComments extracts licenses from the top comment of pom.xml using the license classifier.
// It uses the ContextLicenseScanner which must be available in the context.
// If no licenses are found in the top comment, it falls back to scanning the entire file.
func ExtractLicensesFromComments(ctx context.Context, rawXML string) ([]License, error) {
	if rawXML == "" {
		return nil, nil
	}

	scanner, err := licenses.ContextLicenseScanner(ctx)
	if err != nil {
		log.WithFields("error", err).Debug("unable to get license scanner for comment extraction")
		return nil, nil
	}

	textToScan := extractTopComment(rawXML)
	if textToScan == "" {
		textToScan = rawXML
	}

	evidence, _, err := scanner.FindEvidence(ctx, strings.NewReader(textToScan))
	if err != nil {
		log.WithFields("error", err).Debug("error scanning for licenses in comments")
		return nil, nil
	}

	if len(evidence) == 0 {
		return nil, nil
	}

	return convertEvidenceToLicenses(evidence), nil
}

// extractTopComment extracts the first XML comment from the rawXML.
// Returns the comment content if found, otherwise empty string.
func extractTopComment(rawXML string) string {
	matches := xmlCommentPattern.FindStringSubmatch(rawXML)
	if len(matches) < 2 {
		return ""
	}
	return matches[1]
}

// convertEvidenceToLicenses converts license evidence to License objects.
// Each unique license ID is converted to a License with the ID as both name and no URL.
func convertEvidenceToLicenses(evidence []licenses.Evidence) []License {
	seen := make(map[string]bool)
	var out []License

	for _, ev := range evidence {
		if seen[ev.ID] {
			continue
		}
		seen[ev.ID] = true

		id := ev.ID
		out = append(out, License{
			Name: &id,
		})
	}

	return out
}
