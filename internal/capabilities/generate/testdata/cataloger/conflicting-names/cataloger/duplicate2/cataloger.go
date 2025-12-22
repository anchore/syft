package duplicate2

import (
	"context"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

type Config struct {
	Option2 string
}

func NewDuplicateCataloger(_ Config) pkg.Cataloger {
	return generic.NewCataloger("duplicate-cataloger").
		WithParserByGlobs(parse, "**/*.json")
}

func parse(_ context.Context, _ file.Resolver, _ *generic.Environment, _ file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	return nil, nil, nil
}
