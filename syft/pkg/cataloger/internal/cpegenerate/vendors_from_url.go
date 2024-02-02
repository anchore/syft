package cpegenerate

import (
	"regexp"
	"strings"

	"github.com/anchore/syft/internal"
)

var (
	urlPrefixToVendors = map[string][]string{
		"https://www.gnu.org/":         {"gnu"},
		"https://developer.gnome.org/": {"gnome"},
		"https://www.ruby-lang.org/":   {"ruby-lang"},
		"https://llvm.org/":            {"llvm"},
		"https://www.isc.org/":         {"isc"},
		"https://musl.libc.org/":       {"musl-libc"},
		"https://www.mozilla.org/":     {"mozilla"},
		"https://www.x.org/":           {"x.org"},
		"https://w1.fi/":               {"w1.fi"},
	}

	vendorExtractionPatterns = []*regexp.Regexp{
		regexp.MustCompile(`^(?:https|http|git)://(?:github|gitlab)\.com/(?P<vendor>[\w\-]*?)/.*$`),
	}
)

func candidateVendorsFromURL(url string) fieldCandidateSet {
	vendors := newFieldCandidateSet()

	for urlPrefix, additionalVendors := range urlPrefixToVendors {
		if strings.HasPrefix(url, urlPrefix) {
			for _, v := range additionalVendors {
				vendors.add(fieldCandidate{
					value:                       v,
					disallowSubSelections:       true,
					disallowDelimiterVariations: true,
				})

				return vendors
			}
		}
	}

	for _, p := range vendorExtractionPatterns {
		groups := internal.MatchNamedCaptureGroups(p, url)

		if v, ok := groups["vendor"]; ok {
			vendors.add(fieldCandidate{
				value:                       v,
				disallowSubSelections:       true,
				disallowDelimiterVariations: true,
			})

			return vendors
		}
	}

	return vendors
}
