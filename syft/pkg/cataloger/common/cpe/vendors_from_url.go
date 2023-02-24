package cpe

import (
	"strings"
)

var (
	urlPrefixVendors = map[string][]string{
		"https://www.gnu.org/":         {"gnu"},
		"https://developer.gnome.org/": {"gnome"},
		"https://www.ruby-lang.org/":   {"ruby-lang"},
		"https://llvm.org/":            {"llvm"},
	}
)

func candidateVendorsFromURL(url string) fieldCandidateSet {
	vendors := newFieldCandidateSet()

	for urlPrefix, additionalVendors := range urlPrefixVendors {
		if strings.HasPrefix(url, urlPrefix) {
			for _, v := range additionalVendors {
				vendors.add(fieldCandidate{
					value:                       v,
					disallowSubSelections:       true,
					disallowDelimiterVariations: true,
				})
			}
		}
	}

	return vendors
}
