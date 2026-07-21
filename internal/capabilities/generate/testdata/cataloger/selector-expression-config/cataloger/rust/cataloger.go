package rust

import (
	"context"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// CatalogerConfig is imported from a selector expression in the real code
type CatalogerConfig struct {
	SomeOption bool
}

func NewRustCataloger(_ CatalogerConfig) pkg.Cataloger {
	return generic.NewCataloger("rust-cataloger").
		WithParserByGlobs(parse, "**/Cargo.toml")
}

func parse(_ context.Context, _ file.Resolver, _ *generic.Environment, _ file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	return nil, nil, nil
}
