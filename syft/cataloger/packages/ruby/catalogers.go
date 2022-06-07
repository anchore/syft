/*
Package ruby bundler provides a concrete Cataloger implementation for Ruby Gemfile.lock bundler files.
*/
package ruby

import (
	"github.com/anchore/syft/syft/cataloger/packages/generic"
)

// NewGemFileLockCataloger returns a new Bundler cataloger object tailored for parsing index-oriented files (e.g. Gemfile.lock).
func NewGemFileLockCataloger() *generic.Cataloger {
	globParsers := map[string]generic.Parser{
		"**/Gemfile.lock": parseGemFileLockEntries,
	}

	return generic.NewCataloger(nil, globParsers)
}

// NewGemSpecCataloger returns a new Bundler cataloger object tailored for detecting installations of gems (e.g. Gemspec).
func NewGemSpecCataloger() *generic.Cataloger {
	globParsers := map[string]generic.Parser{
		"**/specifications/**/*.gemspec": parseGemSpecEntries,
	}

	return generic.NewCataloger(nil, globParsers)
}
