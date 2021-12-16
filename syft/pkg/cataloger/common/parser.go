package common

import (
	"io"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
)

// ParserFn standardizes a function signature for parser functions that accept the virtual file path (not usable for file reads) and contents and return any discovered packages from that file
type ParserFn func(string, io.Reader) ([]*pkg.Package, []artifact.Relationship, error)
