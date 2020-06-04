package common

import (
	"io"

	"github.com/anchore/imgbom/imgbom/pkg"
)

type ParserFn func(io.Reader) ([]pkg.Package, error)
