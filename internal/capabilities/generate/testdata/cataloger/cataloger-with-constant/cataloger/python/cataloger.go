package python

import (
	"context"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const catalogerName = "python-package-cataloger"

type CatalogerConfig struct {
	Setting string
}

func NewPythonCataloger(_ CatalogerConfig) pkg.Cataloger {
	return generic.NewCataloger(catalogerName).
		WithParserByGlobs(parse, "**/*.py")
}

func parse(_ context.Context, _ file.Resolver, _ *generic.Environment, _ file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	return nil, nil, nil
}
