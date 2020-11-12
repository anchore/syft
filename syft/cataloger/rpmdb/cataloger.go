/*
Package rpmdb provides a concrete Cataloger implementation for RPM "Package" DB files.
*/
package rpmdb

import (
	"fmt"
	"strings"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/scope"
)

const (
	packagesGlob = "**/var/lib/rpm/Packages"
)

type Cataloger struct{}

// NewRpmdbCataloger returns a new RPM DB cataloger object.
func NewRpmdbCataloger() *Cataloger {
	return &Cataloger{}
}

// Name returns a string that uniquely describes a cataloger
func (c *Cataloger) Name() string {
	return "rpmdb-cataloger"
}

// Catalog is given an object to resolve file references and content, this function returns any discovered Packages after analyzing rpm db installation.
func (c *Cataloger) Catalog(resolver scope.Resolver) ([]pkg.Package, error) {
	fileMatches, err := resolver.FilesByGlob(packagesGlob)
	if err != nil {
		return nil, fmt.Errorf("failed to find rpmdb's by glob: %w", err)
	}

	var pkgs []pkg.Package
	for _, dbRef := range fileMatches {
		dbContents, err := resolver.FileContentsByRef(dbRef)
		if err != nil {
			return nil, err
		}

		pkgs, err = parseRpmDB(resolver, dbRef, strings.NewReader(dbContents))
		if err != nil {
			return nil, fmt.Errorf("unable to catalog rpmdb package=%+v: %w", dbRef.Path, err)
		}
	}
	return pkgs, nil
}
