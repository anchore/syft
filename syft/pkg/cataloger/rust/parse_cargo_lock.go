package rust

import (
	"fmt"
	"io"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/common"
	"github.com/pelletier/go-toml"
)

// integrity check
var _ common.ParserFn = parseCargoLock

// parseCargoLock is a parser function for Cargo.lock contents, returning all rust cargo crates discovered.
func parseCargoLock(_ string, reader io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
	tree, err := toml.LoadReader(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to load Cargo.lock for parsing: %v", err)
	}

	metadata := pkg.CargoMetadata{}
	err = tree.Unmarshal(&metadata)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse Cargo.lock: %v", err)
	}

	return metadata.Pkgs(), nil, nil
}
