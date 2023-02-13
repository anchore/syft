package cpe

import (
	"fmt"
	"strings"

	"github.com/anchore/syft/syft/pkg"
)

func additionalVendorsForPython(v string) (vendors []string) {
	if !strings.HasSuffix(v, "project") {
		vendors = append(vendors, fmt.Sprintf("%sproject", v), fmt.Sprintf("%s_project", v))
	}

	return vendors
}

func candidateVendorsForPython(p pkg.Package) fieldCandidateSet {
	metadata, ok := p.Metadata.(pkg.PythonPackageMetadata)
	if !ok {
		return nil
	}

	vendors := newFieldCandidateSet()

	if metadata.Author != "" {
		name := normalizePersonName(metadata.Author)
		vendors.add(fieldCandidate{
			value:                       name,
			disallowSubSelections:       true,
			disallowDelimiterVariations: true,
		})

		for _, v := range additionalVendorsForPython(name) {
			vendors.add(fieldCandidate{
				value:                       v,
				disallowSubSelections:       true,
				disallowDelimiterVariations: true,
			})
		}
	}

	if metadata.AuthorEmail != "" {
		name := normalizePersonName(stripEmailSuffix(metadata.AuthorEmail))
		vendors.add(fieldCandidate{
			value:                 name,
			disallowSubSelections: true,
		})

		for _, v := range additionalVendorsForPython(name) {
			vendors.add(fieldCandidate{
				value:                       v,
				disallowSubSelections:       true,
				disallowDelimiterVariations: true,
			})
		}
	}

	return vendors
}
