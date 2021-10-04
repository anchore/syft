/*
Package golang provides a concrete Cataloger implementation for go.mod files.
*/
package golang

import (
	"fmt"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

const catalogerName = "go-bin-cataloger"

var mimeTypes = []string{
	"application/x-executable",
	"application/x-mach-binary",
	"application/x-elf",
	"application/x-sharedlib",
	"application/vnd.microsoft.portable-executable",
}

type Cataloger struct{}

// NewGolangCataloger returns a new Golang cataloger object.
func NewGolangCataloger() *Cataloger {
	return &Cataloger{}
}

// Name returns a string that uniquely describes a cataloger
func (c *Cataloger) Name() string {
	return catalogerName
}

// Catalog is given an object to resolve file references and content, this function returns any discovered Packages after analyzing rpm db installation.
func (c *Cataloger) Catalog(resolver source.FileResolver) ([]pkg.Package, error) {
	fileMatches, err := resolver.FilesByMIMEType(mimeTypes...)
	if err != nil {
		return nil, fmt.Errorf("failed to find rpmdb's by glob: %w", err)
	}

	var pkgs []pkg.Package
	for _, location := range fileMatches {
		r, err := resolver.FileContentsByLocation(location)
		if err != nil {
			//TODO
		}

		goPkgs, err := parseGoBin(location.RealPath, r)
		if err != nil {
			//TODO
		}

		pkgs = append(pkgs, goPkgs...)
	}

	return pkgs, nil
}
