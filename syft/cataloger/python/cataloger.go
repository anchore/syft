/*
Package python provides a concrete Cataloger implementation for Python ecosystem files (egg, wheel, requirements.txt).
*/
package python

import (
	"io"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/cataloger/common"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/scope"
)

// Cataloger catalogs pkg.WheelPkg, pkg.EggPkg, and pkg.PythonRequirementsPkg Package Types defined in Python ecosystem files.
type Cataloger struct {
	cataloger common.GenericCataloger
}

// New returns a new Python cataloger object.
func New() *Cataloger {
	globParsers := map[string]common.ParserFn{
		"**/*egg-info/PKG-INFO":  parseEggMetadata,
		"**/*dist-info/METADATA": parseWheelMetadata,
		"**/requirements.txt":    parseRequirementsTxt,
		"**/poetry.lock":         parsePoetryLock,
		"**/setup.py":            parseSetup,
	}

	return &Cataloger{
		cataloger: common.NewGenericCataloger(nil, globParsers),
	}
}

// Name returns a string that uniquely describes this cataloger.
func (c *Cataloger) Name() string {
	return "python-cataloger"
}

// SelectFiles returns a set of discovered Python ecosystem files from the user content source.
func (c *Cataloger) SelectFiles(resolver scope.FileResolver) []file.Reference {
	return c.cataloger.SelectFiles(resolver)
}

// Catalog returns the Packages indexed from all Python ecosystem files discovered.
func (c *Cataloger) Catalog(contents map[file.Reference]io.Reader) ([]pkg.Package, error) {
	return c.cataloger.Catalog(contents)
}
