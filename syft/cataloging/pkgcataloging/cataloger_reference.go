package pkgcataloging

import "github.com/anchore/syft/syft/pkg"

type CatalogerReference struct {
	Cataloger     pkg.Cataloger
	AlwaysEnabled bool
	Tags          []string
}

func NewCatalogerReference(cataloger pkg.Cataloger, tags []string) CatalogerReference {
	return CatalogerReference{
		Cataloger: cataloger,
		Tags:      tags,
	}
}

func NewAlwaysEnabledCatalogerReference(cataloger pkg.Cataloger) CatalogerReference {
	return CatalogerReference{
		Cataloger:     cataloger,
		AlwaysEnabled: true,
	}
}
