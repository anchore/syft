package helpers

import (
	"github.com/anchore/syft/syft/pkg"
)

func ExternalRefs(p pkg.Package) (externalRefs []ExternalRef) {
	externalRefs = make([]ExternalRef, 0)

	for _, c := range p.CPEs {
		externalRefs = append(externalRefs, ExternalRef{
			ReferenceCategory: SecurityReferenceCategory,
			ReferenceLocator:  c.Attributes.String(),
			ReferenceType:     Cpe23ExternalRefType,
		})
	}

	if p.PURL != "" {
		externalRefs = append(externalRefs, ExternalRef{
			ReferenceCategory: PackageManagerReferenceCategory,
			ReferenceLocator:  p.PURL,
			ReferenceType:     PurlExternalRefType,
		})
	}

	return externalRefs
}
