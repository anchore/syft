package dart

import (
	"context"
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

type pubspecPackage struct {
	Name    string `yaml:"name" mapstructure:"name"`
	Version string `yaml:"version" mapstructure:"version"`
}

func parsePubspec(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var pkgs []pkg.Package

	dec := yaml.NewDecoder(reader)

	var p pubspecPackage
	if err := dec.Decode(&p); err != nil {
		return nil, nil, fmt.Errorf("failed to parse pubspec.yml file: %w", err)
	}

	pkgs = append(pkgs,
		newPubspecPackage(
			p,
			reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		),
	)

	return pkgs, nil, nil
}
