package golang

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

type CatalogerConfig struct {
	SomeOption bool
}

func NewGoModuleCataloger(cfg CatalogerConfig) pkg.Cataloger {
	return generic.NewCataloger("go-module-cataloger").
		WithParserByGlobs(parseGoMod, "**/go.mod")
}

func parseGoMod(path string, reader any) ([]pkg.Package, []pkg.Relationship, error) {
	return nil, nil, nil
}
