/*
Package conda provides a concrete Cataloger implementation for packages within the Conda ecosystem.
*/
package conda

import (
	"context"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// NewCondaCataloger returns a new cataloger object for Conda environments.
func NewCondaCataloger() pkg.Cataloger {
	return generic.NewCataloger("conda-cataloger").
		WithParserByGlobs(parseCondaMeta, "**/conda-meta/*.json")
}

// parseCondaMeta is a stub parser for conda-meta JSON files.
func parseCondaMeta(_ context.Context, _ file.Resolver, _ *generic.Environment, _ file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	return nil, nil, nil
}
