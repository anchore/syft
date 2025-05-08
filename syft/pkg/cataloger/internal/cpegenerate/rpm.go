package cpegenerate

import "github.com/anchore/syft/syft/pkg"

func candidateVendorsForRPM(p pkg.Package) fieldCandidateSet {
	vendors := newFieldCandidateSet()

	switch m := p.Metadata.(type) {
	case pkg.RpmDBEntry:
		if m.Vendor != "" {
			vendors.add(fieldCandidate{
				value:                 normalizeName(m.Vendor),
				disallowSubSelections: true,
			})
		}
	case pkg.RpmArchive:
		if m.Vendor != "" {
			vendors.add(fieldCandidate{
				value:                 normalizeName(m.Vendor),
				disallowSubSelections: true,
			})
		}
	}

	return vendors
}
