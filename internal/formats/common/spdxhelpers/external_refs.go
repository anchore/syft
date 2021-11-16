package spdxhelpers

import (
	"github.com/anchore/syft/internal/formats/spdx22json/model"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
)

func ExternalRefs(p pkg.Package) (externalRefs []model.ExternalRef) {
	externalRefs = make([]model.ExternalRef, 0)

	for _, c := range p.CPEs {
		externalRefs = append(externalRefs, model.ExternalRef{
			ReferenceCategory: model.SecurityReferenceCategory,
			ReferenceLocator:  c.BindToFmtString(),
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

func ExtractPURL(refs []model.ExternalRef) string {
	for _, r := range refs {
		if r.ReferenceType == model.PurlExternalRefType {
			return r.ReferenceLocator
		}
	}
	return ""
}

func ExtractCPEs(refs []model.ExternalRef) (cpes []pkg.CPE) {
	for _, r := range refs {
		if r.ReferenceType == model.Cpe23ExternalRefType {
			cpe, err := pkg.NewCPE(r.ReferenceLocator)
			if err != nil {
				log.Warnf("unable to extract SPDX CPE=%q: %+v", r.ReferenceLocator, err)
				continue
			}
			cpes = append(cpes, cpe)
		}
	}
	return cpes
}
