/*
Package rpmdb provides a concrete Cataloger implementation for RPM "Package" DB files.
*/
package rpmdb

import (
	"fmt"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

const (
	packagesGlob  = "**/var/lib/rpm/Packages"
	catalogerName = "rpmdb-cataloger"
)

type Cataloger struct{}

// NewRpmdbCataloger returns a new RPM DB cataloger object.
func NewRpmdbCataloger() *Cataloger {
	return &Cataloger{}
}

// Name returns a string that uniquely describes a cataloger
func (c *Cataloger) Name() string {
	return catalogerName
}

// Catalog is given an object to resolve file references and content, this function returns any discovered Packages after analyzing rpm db installation.
func (c *Cataloger) Catalog(resolver source.Resolver) ([]pkg.Package, error) {
	fileMatches, err := resolver.FilesByGlob(packagesGlob)
	if err != nil {
		return nil, fmt.Errorf("failed to find rpmdb's by glob: %w", err)
	}

	var pkgs []pkg.Package
	for _, location := range fileMatches {
		dbContentReader, err := resolver.FileContentsByLocation(location)
		if err != nil {
			return nil, err
		}

		pkgs, err = parseRpmDB(resolver, location, dbContentReader)
		if err != nil {
			return nil, fmt.Errorf("unable to catalog rpmdb package=%+v: %w", location.Path, err)
		}
	}
	return pkgs, nil
}
