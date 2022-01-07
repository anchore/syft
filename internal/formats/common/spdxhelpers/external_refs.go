package spdxhelpers

import (
	"github.com/anchore/syft/internal/formats/spdx22json/model"
	"github.com/anchore/syft/syft/pkg"
)

func ExternalRefs(p pkg.Package) (externalRefs []model.ExternalRef) {
	externalRefs = make([]model.ExternalRef, 0)

	for _, c := range p.CPEs {
		externalRefs = append(externalRefs, model.ExternalRef{
			ReferenceCategory: model.SecurityReferenceCategory,
			ReferenceLocator:  pkg.CPEString(c),
			ReferenceType:     model.Cpe23ExternalRefType,
		})
	}

	if p.PURL != "" {
		externalRefs = append(externalRefs, model.ExternalRef{
			ReferenceCategory: model.PackageManagerReferenceCategory,
			ReferenceLocator:  p.PURL,
			ReferenceType:     model.PurlExternalRefType,
		})
	}
	return externalRefs
}
