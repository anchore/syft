package ruby

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

type Config struct {
	Setting bool
}

func NewRubyCataloger(opts Config) pkg.Cataloger {
	return generic.NewCataloger("ruby-cataloger").
		WithParserByGlobs(parse, "**/Gemfile")
}

func parse(path string, reader any) ([]pkg.Package, []pkg.Relationship, error) {
	return nil, nil, nil
}
