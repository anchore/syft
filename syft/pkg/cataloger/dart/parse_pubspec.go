package dart

import (
	"context"
	"fmt"

	"go.yaml.in/yaml/v3"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

type pubspecPackage struct {
	Name              string                 `mapstructure:"name" yaml:"name"`
	Version           string                 `mapstructure:"version" yaml:"version"`
	Homepage          string                 `mapstructure:"homepage" yaml:"homepage"`
	Repository        string                 `mapstructure:"repository" yaml:"repository"`
	Documentation     string                 `mapstructure:"documentation" yaml:"documentation"`
	PublishTo         string                 `mapstructure:"publish_to" yaml:"publish_to"`
	Environment       dartPubspecEnvironment `mapstructure:"environment" yaml:"environment"`
	Platforms         []string               `mapstructure:"platforms" yaml:"platforms"`
	IgnoredAdvisories []string               `mapstructure:"ignored_advisories" yaml:"ignored_advisories"`
}

type dartPubspecEnvironment struct {
	SDK     string `mapstructure:"sdk" yaml:"sdk"`
	Flutter string `mapstructure:"flutter" yaml:"flutter"`
}

func parsePubspec(ctx context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var pkgs []pkg.Package

	dec := yaml.NewDecoder(reader)

	var p pubspecPackage
	if err := dec.Decode(&p); err != nil {
		return nil, nil, fmt.Errorf("failed to parse pubspec.yml file: %w", err)
	}

	pkgs = append(pkgs,
		newPubspecPackage(
			ctx,
			resolver,
			p,
			reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		),
	)

	return pkgs, nil, nil
}
