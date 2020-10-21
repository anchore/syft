package python

import (
	"fmt"
	"path/filepath"

	"github.com/anchore/stereoscope/pkg/file"

	"github.com/anchore/syft/syft/pkg"

	"github.com/anchore/syft/syft/scope"
)

const wheelGlob = "**/*dist-info/METADATA"

type PackageCataloger struct {
	globs []string
}

// NewPythonPackageCataloger returns a new cataloger for python packages within egg or wheel installation directories.
func NewPythonPackageCataloger() *PackageCataloger {
	//globParsers := map[string]common.ParserFn{
	//	"**/*egg-info/PKG-INFO":  parseWheelOrEggMetadata,
	//	"**/*dist-info/METADATA": parseWheelOrEggMetadata,
	//}

	return &PackageCataloger{}
}

func (c *PackageCataloger) Name() string {
	return "python-package-cataloger"
}

func (c *PackageCataloger) Catalog(resolver scope.Resolver) ([]pkg.Package, error) {
	return c.catalogWheels(resolver)
}

func (c *PackageCataloger) catalogWheels(resolver scope.Resolver) ([]pkg.Package, error) {
	fileMatches, err := resolver.FilesByGlob(wheelGlob)
	if err != nil {
		return nil, fmt.Errorf("failed to find files by glob: %s", wheelGlob)
	}

	var pkgs []pkg.Package
	for _, ref := range fileMatches {
		p, err := c.catalogWheel(resolver, ref)
		if err != nil {
			return nil, fmt.Errorf("unable to catalog python wheel=%+v: %w", ref.Path, err)
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, nil
}

func (c *PackageCataloger) catalogWheel(resolver scope.Resolver, wheelRef file.Reference) (pkg.Package, error) {
	// we've been given a file reference to a specific wheel METADATA file. note: this may be for a directory
	// or for an image... for an image the METADATA file may be present within multiple layers, so it is important
	// to reconcile the RECORD path to the same layer (or the next adjacent lower layer).
	recordPath := filepath.Join(filepath.Dir(string(wheelRef.Path)), "RECORD")

	// problem! we don't know which is the right discovered path relative to the given METADATA file! (which layer?)
	discoveredPaths, err := resolver.FilesByPath(file.Path(recordPath))

}
