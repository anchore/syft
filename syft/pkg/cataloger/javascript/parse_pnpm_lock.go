package javascript

import (
	"fmt"
	"io"

	"gopkg.in/yaml.v3"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/source"
)

// integrity check
var _ generic.Parser = parsePnpmLock

type pnpmLockYaml struct {
	Dependencies map[string]string `json:"dependencies"`
}

func parsePnpmLock(resolver source.FileResolver, _ *generic.Environment, reader source.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	bytes, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load pnpm-lock.yaml file: %w", err)
	}

	var pkgs []pkg.Package
	var lockFile pnpmLockYaml

	if err := yaml.Unmarshal(bytes, &lockFile); err != nil {
		return nil, nil, fmt.Errorf("failed to parse pnpm-lock.yaml file: %w", err)
	}

	for name, version := range lockFile.Dependencies {
		pkgs = append(pkgs, newPnpmPackage(resolver, reader.Location, name, version))
	}

	pkg.Sort(pkgs)

	return pkgs, nil, nil
}
