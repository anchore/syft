package cpe

import (
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/cpegenerate"
)

func Create(p pkg.Package) []cpe.CPE {
	dictionaryCPE, ok := cpegenerate.FromDictionaryFind(p)
	if ok {
		return []cpe.CPE{dictionaryCPE}
	}

	return cpegenerate.FromPackageAttributes(p)
}
