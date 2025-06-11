/*
Package conda provides a concrete Cataloger implementation for packages within the Conda ecosystem.
*/
package conda

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// NewCondaMetaCataloger returns a new cataloger object for Conda environments.
func NewCondaMetaCataloger() pkg.Cataloger {
	return generic.NewCataloger("conda-meta-cataloger").
		WithParserByGlobs(parseCondaMeta, "**/conda-meta/*.json")
}

// parseCondaMeta is a stub parser for conda-meta JSON files.
func parseCondaMeta(ctx context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	dec := json.NewDecoder(reader)
	var meta pkg.CondaMetaPackage
	if err := dec.Decode(&meta); err != nil {
		return nil, nil, fmt.Errorf("failed to parse conda-meta package file: %w", err)
	}

	p := pkg.Package{
		Name:      meta.Name,
		Version:   meta.Version,
		PURL:      fmt.Sprintf("pkg:generic/%s@%s", meta.Name, meta.Version),
		Locations: file.NewLocationSet(reader.Location),
		Licenses: pkg.NewLicenseSet(
			pkg.NewLicenseFromLocationsWithContext(ctx, meta.License, reader.Location),
		),
		Language: pkg.UnknownLanguage,
		Type:     pkg.CondaPkg,
		Metadata: meta,
	}

	p.SetID()

	pkgs := []pkg.Package{
		p,
	}

	return pkgs, nil, nil
}
