/*
Package golang provides a concrete Cataloger implementation for go.mod files.
*/
package golang

import (
	"fmt"
	"os"

	"github.com/anchore/syft/internal"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

const catalogerName = "go-module-binary-cataloger"

type Cataloger struct{}

// NewGoModuleBinaryCataloger returns a new Golang cataloger object.
func NewGoModuleBinaryCataloger() *Cataloger {
	return &Cataloger{}
}

// Name returns a string that uniquely describes a cataloger
func (c *Cataloger) Name() string {
	return catalogerName
}

// Catalog is given an object to resolve file references and content, this function returns any discovered Packages after analyzing rpm db installation.
func (c *Cataloger) Catalog(resolver source.FileResolver) ([]pkg.Package, []artifact.Relationship, error) {
	var pkgs []pkg.Package

	fileMatches, err := resolver.FilesByMIMEType(internal.ExecutableMIMETypeSet.List()...)
	if err != nil {
		return pkgs, nil, fmt.Errorf("failed to find bin by mime types: %w", err)
	}

	for _, location := range fileMatches {
		info, err := os.Stat(location.RealPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			continue
		}
		mod := scanFile(location.RealPath, info)

		pkgs = append(pkgs, buildGoPkgInfo(location, mod)...)
	}

	return pkgs, nil, nil
}
