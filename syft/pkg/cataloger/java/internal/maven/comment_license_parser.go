package maven

import (
	"context"
	"regexp"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/licenses"
)

var xmlCommentPattern = regexp.MustCompile(`(?s)<!--(.*?)-->`)
var plainURLPattern = regexp.MustCompile(`https?://[^\s<>"')]+`)

// ExtractLicensesFromComments extracts licenses from the top comment of pom.xml using the license classifier.
// It uses the ContextLicenseScanner which must be available in the context.
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
		return nil, nil
	}

	evidence, raw, err := scanner.FindEvidence(ctx, strings.NewReader(textToScan))
	if err != nil {
		log.WithFields("error", err).Debug("error scanning for licenses in comments")
		return nil, nil
	}

	if len(evidence) == 0 {
		return nil, nil
	}

	out := convertEvidenceToLicenses(evidence, raw)
	enrichLicenseURLsFromText(out, string(raw))

	return out, nil
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
func convertEvidenceToLicenses(evidence []licenses.Evidence, raw []byte) []License {
	licenseIdxByID := make(map[string]int)
	out := make([]License, 0, len(evidence))

	for _, ev := range evidence {
		if ev.ID == "" {
			continue
		}

		idx, exists := licenseIdxByID[ev.ID]
		if !exists {
			id := ev.ID
			out = append(out, License{
				Name: &id,
			})
			idx = len(out) - 1
			licenseIdxByID[ev.ID] = idx
		}

		if ev.IsURL && out[idx].URL == nil && ev.Start >= 0 && ev.End <= len(raw) && ev.End >= ev.Start {
			url := strings.TrimSpace(string(raw[ev.Start:ev.End]))
			if url != "" {
				out[idx].URL = &url
			}
		}
	}

	return out
}

func enrichLicenseURLsFromText(found []License, text string) {
	if len(found) != 1 || found[0].URL != nil {
		return
	}

	urls := plainURLPattern.FindAllString(text, -1)
	if len(urls) != 1 {
		return
	}

	url := strings.TrimRight(urls[0], ".,;)")
	if url == "" {
		return
	}

	found[0].URL = &url
}
