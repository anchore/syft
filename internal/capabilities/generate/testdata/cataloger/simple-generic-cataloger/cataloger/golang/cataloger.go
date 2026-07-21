package golang

import (
	"context"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

type CatalogerConfig struct {
	SomeOption bool
}

func NewGoModuleCataloger(_ CatalogerConfig) pkg.Cataloger {
	return generic.NewCataloger("go-module-cataloger").
		WithParserByGlobs(parseGoMod, "**/go.mod")
}

func parseGoMod(_ context.Context, _ file.Resolver, _ *generic.Environment, _ file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	return nil, nil, nil
}
