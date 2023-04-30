package javascript

import (
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// integrity check
var _ generic.Parser = parsePnpmLock

type pnpmLockYaml struct {
	Dependencies map[string]string      `json:"dependencies"`
	Packages     map[string]interface{} `json:"packages"`
}

func parsePnpmLock(resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
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

	// parse packages from packages section of pnpm-lock.yaml
	for nameVersion := range lockFile.Packages {
		nameVersionSplit := strings.Split(strings.TrimPrefix(nameVersion, "/"), "/")

		// last element in split array is version
		version := nameVersionSplit[len(nameVersionSplit)-1]

		// construct name from all array items other than last item (version)
		name := strings.Join(nameVersionSplit[:len(nameVersionSplit)-1], "/")

		pkgs = append(pkgs, newPnpmPackage(resolver, reader.Location, name, version))
	}

	pkg.Sort(pkgs)

	return pkgs, nil, nil
}
