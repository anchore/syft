package cpe

import (
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/cpegenerate"
)

func Generate(p pkg.Package) []cpe.CPE {
	return cpegenerate.FromPackageAttributes(p)
}

func DictionaryFind(p pkg.Package) (cpe.CPE, bool) {
	c, ok := cpegenerate.FromDictionaryFind(p)
	return c.WithNVDDictionarySource(), ok
}
