package beam

import (
	"io"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
)

// parseMixLock parses a mix.exs and returns the discovered Elixir packages.
func parseMixExs(_ string, reader io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
	return nil, nil, nil
}
