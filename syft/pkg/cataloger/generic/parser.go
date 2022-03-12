package generic

import (
	"github.com/anchore/syft/syft/pkg"
	"io"

	"github.com/anchore/syft/syft/artifact"
)

// Parser standardizes a function signature for parser functions that accept the virtual file path (not usable for file reads) and contents and return any discovered packages from that file
type Parser func(string, io.Reader) ([]*pkg.Package, []artifact.Relationship, error)
