/*
Package golang provides a concrete Cataloger implementation for go.mod files.
*/
package golang

import (
	"fmt"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

const catalogerName = "go-module-binary-cataloger"

// current mime types to search by to discover go binaries
var mimeTypes = []string{
	"application/x-executable",
	"application/x-mach-binary",
	"application/x-elf",
	"application/x-sharedlib",
	"application/vnd.microsoft.portable-executable",
}

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
func (c *Cataloger) Catalog(resolver source.FileResolver) ([]pkg.Package, error) {
	pkgs := make([]pkg.Package, 0)
	fileMatches, err := resolver.FilesByMIMEType(mimeTypes...)
	if err != nil {
		return pkgs, fmt.Errorf("failed to find bin by mime types: %w", err)
	}

	for _, location := range fileMatches {
		r, err := resolver.FileContentsByLocation(location)
		if err != nil {
			return pkgs, fmt.Errorf("failed to resolve file contents by location: %w", err)
		}

		goPkgs, err := parseGoBin(location.RealPath, r)
		if err != nil {
			log.Infof("could not parse go bin for: %w", err)
		}

		r.Close()
		pkgs = append(pkgs, goPkgs...)
	}

	return pkgs, nil
}
