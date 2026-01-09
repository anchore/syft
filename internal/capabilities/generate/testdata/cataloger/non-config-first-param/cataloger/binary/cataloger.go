package binary

import (
	"context"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

type Parser struct{}

func NewBinaryCataloger(_ Parser) pkg.Cataloger {
	return generic.NewCataloger("binary-cataloger").
		WithParserByGlobs(parse, "**/*")
}

func parse(_ context.Context, _ file.Resolver, _ *generic.Environment, _ file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	return nil, nil, nil
}
