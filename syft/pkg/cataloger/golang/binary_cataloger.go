/*
Package golang provides a concrete Cataloger implementation for go.mod files.
*/
package golang

import (
	"fmt"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
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
		readerCloser, err := resolver.FileContentsByLocation(location)
		if err != nil {
			log.Debugf("golang cataloger: opening file: %v", err)
			continue
		}

		reader, ok := readerCloser.(file.LazyReader)
		if !ok {
			log.Warnf("golang cataloger: resolver cannot provide file reader")
			continue
		}

		metadata, err := resolver.FileMetadataByLocation(location)
		if err != nil {
			log.Debugf("golang cataloger: getting location metadata: %v", err)
			continue
		}

		mods := scanFile(reader, location.RealPath, metadata.Mode)
		internal.CloseAndLogError(readerCloser, location.RealPath)

		for _, mod := range mods {
			pkgs = append(pkgs, buildGoPkgInfo(location, mod)...)
		}
	}

	return pkgs, nil, nil
}
