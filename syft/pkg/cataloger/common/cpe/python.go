package cpe

import "github.com/anchore/syft/syft/pkg"

func candidateVendorsForPython(p pkg.Package) *fieldCandidateSet {
	metadata, ok := p.Metadata.(pkg.PythonPackageMetadata)
	if !ok {
		return nil
	}

	vendors := newCPRFieldCandidateSet()

	if metadata.Author != "" {
		vendors.add(fieldCandidate{
			value:                       normalizeName(metadata.Author),
			disallowSubSelections:       true,
			disallowDelimiterVariations: true,
		})
	}

	if metadata.AuthorEmail != "" {
		vendors.add(fieldCandidate{
			value:                 normalizeName(stripEmailSuffix(metadata.AuthorEmail)),
			disallowSubSelections: true,
		})
	}

	return vendors
}
