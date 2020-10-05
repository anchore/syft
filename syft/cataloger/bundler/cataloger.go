/*
Package bundler provides a concrete Cataloger implementation for Ruby Gemfile.lock bundler files.
*/
package bundler

import (
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/cataloger/common"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/scope"
)

// Cataloger catalogs pkg.GemPkg Package Types defined in Bundler Gemfile.lock files.
type Cataloger struct {
	cataloger common.GenericCataloger
}

// New returns a new Bundler cataloger object.
func New() *Cataloger {
	globParsers := map[string]common.ParserFn{
		"**/Gemfile.lock": parseGemfileLockEntries, // valid in a dir context
		//"**/specification/*.gemspec": parseGemSpecEntries,     // valid in an image context (against installed gems)
	}

	return &Cataloger{
		cataloger: common.NewGenericCataloger(nil, globParsers),
	}
}

// Name returns a string that uniquely describes this cataloger.
func (a *Cataloger) Name() string {
	return "bundler-cataloger"
}

// SelectFiles returns a set of discovered Gemfile.lock files from the user content source.
func (a *Cataloger) SelectFiles(resolver scope.FileResolver) []file.Reference {
	return a.cataloger.SelectFiles(resolver)
}

// Catalog returns the Packages indexed from all Gemfile.lock files discovered.
func (a *Cataloger) Catalog(contents map[file.Reference]string) ([]pkg.Package, error) {
	return a.cataloger.Catalog(contents, a.Name())
}
