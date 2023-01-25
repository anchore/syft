/*
Package ruby bundler provides a concrete Cataloger implementation for Ruby Gemfile.lock bundler files.
*/
package ruby

import (
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// NewGemFileLockCataloger returns a new Bundler cataloger object tailored for parsing index-oriented files (e.g. Gemfile.lock).
func NewGemFileLockCataloger() *generic.Cataloger {
	return generic.NewCataloger("ruby-gemfile-cataloger").
		WithParserByBasename(parseGemFileLockEntries, "Gemfile.lock")
}

// NewGemSpecCataloger returns a new Bundler cataloger object tailored for detecting installations of gems (e.g. Gemspec).
func NewGemSpecCataloger() *generic.Cataloger {
	return generic.NewCataloger("ruby-gemspec-cataloger").
		WithParser(parseGemSpecEntries,
			generic.NewSearch().ByExtension("*.gemspec").MustMatchGlob("**/specifications/**/*.gemspec"),
		)
}
