package cpe

import "github.com/anchore/syft/syft/pkg"

func candidateVendorsForJavascript(p pkg.Package) fieldCandidateSet {
	if _, ok := p.Metadata.(pkg.NpmPackage); !ok {
		return nil
	}

	vendors := newFieldCandidateSet()
	metadata, ok := p.Metadata.(pkg.NpmPackage)
	if !ok {
		return nil
	}

	if metadata.URL != "" {
		vendors.union(candidateVendorsFromURL(metadata.URL))
	}

	if metadata.Homepage != "" {
		vendors.union(candidateVendorsFromURL(metadata.Homepage))
	}

	return vendors
}
