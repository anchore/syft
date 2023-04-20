package python

import (
	"fmt"

	"github.com/pelletier/go-toml"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// integrity check
var _ generic.Parser = parsePoetryLock

type poetryMetadata struct {
	Packages []struct {
		Name        string `toml:"name"`
		Version     string `toml:"version"`
		Category    string `toml:"category"`
		Description string `toml:"description"`
		Optional    bool   `toml:"optional"`
	} `toml:"package"`
}

// parsePoetryLock is a parser function for poetry.lock contents, returning all python packages discovered.
func parsePoetryLock(_ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	tree, err := toml.LoadReader(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to load poetry.lock for parsing: %w", err)
	}

	metadata := poetryMetadata{}
	err = tree.Unmarshal(&metadata)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse poetry.lock: %w", err)
	}

	var pkgs []pkg.Package
	for _, p := range metadata.Packages {
		pkgs = append(
			pkgs,
			newPackageForIndex(
				p.Name,
				p.Version,
				reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
			),
		)
	}

	return pkgs, nil, nil
}
