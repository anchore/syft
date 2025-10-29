package python

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const catalogerName = "python-package-cataloger"

type CatalogerConfig struct {
	Setting string
}

func NewPythonCataloger(cfg CatalogerConfig) pkg.Cataloger {
	return generic.NewCataloger(catalogerName).
		WithParserByGlobs(parse, "**/*.py")
}

func parse(path string, reader any) ([]pkg.Package, []pkg.Relationship, error) {
	return nil, nil, nil
}
