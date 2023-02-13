package cpe

import (
	"fmt"
	"strings"

	"github.com/anchore/syft/syft/pkg"
)

func additionalVendorsForPython(v string) fieldCandidateSet {
	vendors := newFieldCandidateSet()

	if !strings.HasSuffix(v, "project") {
		vendors.add(fieldCandidate{
			value:                       fmt.Sprintf("%sproject", v),
			disallowSubSelections:       true,
			disallowDelimiterVariations: true,
		})

		vendors.add(fieldCandidate{
			value:                       fmt.Sprintf("%s_project", v),
			disallowSubSelections:       true,
			disallowDelimiterVariations: true,
		})
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

		vendors.union(additionalVendorsForPython(name))
	}

	if metadata.AuthorEmail != "" {
		name := normalizePersonName(stripEmailSuffix(metadata.AuthorEmail))
		vendors.add(fieldCandidate{
			value:                 name,
			disallowSubSelections: true,
		})
		vendors.union(additionalVendorsForPython(name))
	}

	return vendors
}
