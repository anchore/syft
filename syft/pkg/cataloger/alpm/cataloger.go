package alpm

import (
	"fmt"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

const catalogerName = "alpmdb-cataloger"

type Cataloger struct{}

// NewAlpmdbCataloger returns a new ALPM DB cataloger object.
func NewAlpmdbCataloger() *Cataloger {
	return &Cataloger{}
}

// Name returns a string that uniquely describes a cataloger
func (c *Cataloger) Name() string {
	return catalogerName
}

// UsesExternalSources indicates that the alpmdb cataloger does not use external sources
func (c *Cataloger) UsesExternalSources() bool {
	return false
}

// Catalog is given an object to resolve file references and content, this function returns any discovered Packages after analyzing rpm db installation.
func (c *Cataloger) Catalog(resolver source.FileResolver) ([]pkg.Package, []artifact.Relationship, error) {
	fileMatches, err := resolver.FilesByGlob(pkg.AlpmDBGlob)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find rpmdb's by glob: %w", err)
	}

	var pkgs []pkg.Package
	for _, location := range fileMatches {
		dbContentReader, err := resolver.FileContentsByLocation(location)
		if err != nil {
			return nil, nil, err
		}

		discoveredPkgs, err := parseAlpmDB(resolver, location.RealPath, dbContentReader)
		internal.CloseAndLogError(dbContentReader, location.VirtualPath)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to catalog package=%+v: %w", location.RealPath, err)
		}
		pkgs = append(pkgs, discoveredPkgs...)
	}
	return pkgs, nil, nil
}
