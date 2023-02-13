package cpe

import (
	"strings"

	"github.com/anchore/syft/syft/pkg"
)

var (
	prefixes = []string{"py-", "py2-", "py3-", "ruby-"}
)

func candidateVendorsForAPK(p pkg.Package) fieldCandidateSet {
	metadata, ok := p.Metadata.(pkg.ApkMetadata)
	if !ok {
		return nil
	}

	vendors := newFieldCandidateSet()

	for _, p := range prefixes {
		if strings.HasPrefix(metadata.Package, p) {
			vendors.addValue(strings.TrimPrefix(metadata.Package, p))
		}

		if strings.HasPrefix(metadata.OriginPackage, p) {
			vendors.addValue(strings.TrimPrefix(metadata.OriginPackage, p))
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

	for _, p := range prefixes {
		if strings.HasPrefix(metadata.Package, p) {
			products.addValue(strings.TrimPrefix(metadata.Package, p))
		}

		if strings.HasPrefix(metadata.OriginPackage, p) {
			products.addValue(strings.TrimPrefix(metadata.OriginPackage, p))
		}
	}

	return products
}
