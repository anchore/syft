package python

import (
	"fmt"
	"io"

	"github.com/anchore/syft/syft/pkg"
	"github.com/pelletier/go-toml"
)

func parsePoetryLock(_ string, reader io.Reader) ([]pkg.Package, error) {
	tree, err := toml.LoadReader(reader)
	if err != nil {
		return nil, fmt.Errorf("unable to load poetry.lock for parsing: %v", err)
	}

	metadata := PoetryMetadata{}
	err = tree.Unmarshal(&metadata)
	if err != nil {
		return nil, fmt.Errorf("unable to parse poetry.lock: %v", err)
	}

	return metadata.Pkgs(), nil
}
