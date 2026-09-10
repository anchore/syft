package cpegenerate

import (
	"net/url"
	"strings"

	"github.com/anchore/syft/syft/pkg"
)

func candidateVendorsForRPM(p pkg.Package) fieldCandidateSet {
	vendors := newFieldCandidateSet()
	var vendor string

	switch m := p.Metadata.(type) {
	case pkg.RpmDBEntry:
		vendor = m.Vendor
	case pkg.RpmArchive:
		vendor = m.Vendor
	}

	vendor = stripTrailingURL(vendor)
	if vendor != "" {
		vendors.add(fieldCandidate{
			value:                 normalizeName(vendor),
			disallowSubSelections: true,
		})
	}

	return vendors
}

func stripTrailingURL(value string) string {
	trimmed := strings.TrimSpace(value)
	if !strings.HasSuffix(trimmed, ">") {
		return value
	}

	open := strings.LastIndex(trimmed, "<")
	if open == -1 {
		return value
	}

	parsed, err := url.Parse(trimmed[open+1 : len(trimmed)-1])
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return value
	}

	return strings.TrimSpace(trimmed[:open])
}
