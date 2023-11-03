/*
Package ruby provides a concrete Cataloger implementation relating to packages within the Ruby language ecosystem.
*/
package ruby

import (
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// NewGemFileLockCataloger returns a new Bundler cataloger object tailored for parsing index-oriented files (e.g. Gemfile.lock).
func NewGemFileLockCataloger() *generic.Cataloger {
	return generic.NewCataloger("ruby-gemfile-cataloger").
		WithParserByGlobs(parseGemFileLockEntries, "**/Gemfile.lock")
}

// NewInstalledGemSpecCataloger returns a new Bundler cataloger object tailored for detecting installations of gems (e.g. Gemspec).
func NewInstalledGemSpecCataloger() *generic.Cataloger {
	return generic.NewCataloger("ruby-installed-gemspec-cataloger").
		WithParserByGlobs(parseGemSpecEntries, "**/specifications/**/*.gemspec")
}

// NewGemSpecCataloger looks for gems without the additional requirement of the gem being installed.
func NewGemSpecCataloger() *generic.Cataloger {
	return generic.NewCataloger("ruby-gemspec-cataloger").
		WithParserByGlobs(parseGemSpecEntries, "**/*.gemspec")
}
