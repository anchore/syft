package common

import (
	"io"

	"github.com/anchore/imgbom/imgbom/pkg"
)

// ParserFn standardizes a function signature for parser functions that accept file contents and return any discovered packages from that file
type ParserFn func(io.Reader) ([]pkg.Package, error)
