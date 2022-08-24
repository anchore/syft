package javascript

import (
	"fmt"
	"io"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/common"
	"gopkg.in/yaml.v3"
)

// integrity check
var _ common.ParserFn = parsePnpmLock

type pnpmLockYaml struct {
	Dependencies map[string]string `json:"dependencies"`
}

func parsePnpmLock(path string, reader io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
	bytes, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load pnpm-lock.yaml file: %w", err)
	}

	var pkgs []*pkg.Package
	var lockFile pnpmLockYaml

	if err := yaml.Unmarshal(bytes, &lockFile); err != nil {
		return nil, nil, fmt.Errorf("failed to parse pnpm-lock.yaml file: %w", err)
	}

	for name, version := range lockFile.Dependencies {
		pkgs = append(pkgs, &pkg.Package{
			Name:     name,
			Version:  version,
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
		})
	}

	return pkgs, nil, nil
}
