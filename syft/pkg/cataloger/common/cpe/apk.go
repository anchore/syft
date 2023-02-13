package cpe

import (
	"strings"

	"github.com/anchore/syft/syft/pkg"
)

var (
	pythonPrefixes = []string{"py-", "py2-", "py3-"}
	rubyPrefixes   = []string{"ruby-"}
)

func candidateVendorsForAPK(p pkg.Package) fieldCandidateSet {
	metadata, ok := p.Metadata.(pkg.ApkMetadata)
	if !ok {
		return nil
	}

	vendors := newFieldCandidateSet()

	for _, p := range pythonPrefixes {
		if strings.HasPrefix(metadata.Package, p) {
			t := strings.TrimPrefix(metadata.Package, p)
			vendors.add(fieldCandidate{
				value:                       t,
				disallowSubSelections:       true,
				disallowDelimiterVariations: true,
			})
			vendors.union(additionalVendorsForPython(t))
		}

		if strings.HasPrefix(metadata.OriginPackage, p) {
			t := strings.TrimPrefix(metadata.OriginPackage, p)
			vendors.add(fieldCandidate{
				value:                       t,
				disallowSubSelections:       true,
				disallowDelimiterVariations: true,
			})
			vendors.union(additionalVendorsForPython(t))
		}
	}

	for _, p := range rubyPrefixes {
		if strings.HasPrefix(metadata.Package, p) {
			t := strings.TrimPrefix(metadata.Package, p)
			vendors.addValue(t)
		}

		if strings.HasPrefix(metadata.OriginPackage, p) {
			t := strings.TrimPrefix(metadata.OriginPackage, p)
			vendors.addValue(t)
		}
	}

	return vendors
}

func candidateProductsForAPK(p pkg.Package) fieldCandidateSet {
	metadata, ok := p.Metadata.(pkg.ApkMetadata)
	if !ok {
		return nil
	}

	products := newFieldCandidateSet()

	for _, p := range pythonPrefixes {
		if strings.HasPrefix(metadata.Package, p) {
			products.addValue(strings.TrimPrefix(metadata.Package, p))
		}

		if strings.HasPrefix(metadata.OriginPackage, p) {
			products.addValue(strings.TrimPrefix(metadata.OriginPackage, p))
		}
	}

	for _, p := range rubyPrefixes {
		if strings.HasPrefix(metadata.Package, p) {
			products.addValue(strings.TrimPrefix(metadata.Package, p))
		}

		if strings.HasPrefix(metadata.OriginPackage, p) {
			products.addValue(strings.TrimPrefix(metadata.OriginPackage, p))
		}
	}

	return products
}
