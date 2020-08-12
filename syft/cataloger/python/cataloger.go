package python

import (
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
	}

	return &Cataloger{
		cataloger: common.NewGenericCataloger(nil, globParsers),
	}
}

// Name returns a string that uniquely describes this cataloger.
func (a *Cataloger) Name() string {
	return "python-cataloger"
}

// SelectFiles returns a set of discovered Python ecosystem files from the user content source.
func (a *Cataloger) SelectFiles(resolver scope.FileResolver) []file.Reference {
	return a.cataloger.SelectFiles(resolver)
}

// Catalog returns the Packages indexed from all Python ecosystem files discovered.
func (a *Cataloger) Catalog(contents map[file.Reference]string) ([]pkg.Package, error) {
	return a.cataloger.Catalog(contents, a.Name())
}
