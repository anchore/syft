package rust

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/test/cargo"
)

func NewRustCataloger(cfg cargo.CatalogerConfig) pkg.Cataloger {
	return generic.NewCataloger("rust-cataloger").
		WithParserByGlobs(parse, "**/Cargo.toml")
}

func parse(path string, reader any) ([]pkg.Package, []pkg.Relationship, error) {
	return nil, nil, nil
}
