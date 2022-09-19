package haskell

import (
	"fmt"
	"io"

	"gopkg.in/yaml.v3"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/common"
)

// integrity check
var _ common.ParserFn = parseStackYaml

type stackYaml struct {
	ExtraDeps []string `yaml:"extra-deps"`
}

// parseStackYaml is a parser function for stack.yaml contents, returning all packages discovered.
func parseStackYaml(_ string, reader io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
	bytes, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load stack.yaml file: %w", err)
	}

	var stackFile stackYaml

	if err := yaml.Unmarshal(bytes, &stackFile); err != nil {
		return nil, nil, fmt.Errorf("failed to parse stack.yaml file: %w", err)
	}

	var (
		pkgs []*pkg.Package
	)

	for _, dep := range stackFile.ExtraDeps {
		pkgName, pkgVersion, pkgHash := parseStackPackageEncoding(dep)
		pkgs = append(pkgs, &pkg.Package{
			Name:         pkgName,
			Version:      pkgVersion,
			Language:     pkg.Haskell,
			Type:         pkg.HackagePkg,
			MetadataType: pkg.HackageMetadataType,
			Metadata: pkg.HackageMetadata{
				Name:    pkgName,
				Version: pkgVersion,
				PkgHash: &pkgHash,
			},
		})
	}

	return pkgs, nil, nil
}
