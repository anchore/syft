package cpe

import "github.com/anchore/syft/syft/pkg"

func candidateVendorsForJavascript(p pkg.Package) fieldCandidateSet {
	if p.MetadataType != pkg.NpmPackageJSONMetadataType {
		return nil
	}

	vendors := newFieldCandidateSet()
	metadata, ok := p.Metadata.(pkg.NpmPackageJSONMetadata)
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
