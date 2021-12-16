/*
Package ruby bundler provides a concrete Cataloger implementation for Ruby Gemfile.lock bundler files.
*/
package ruby

import (
	"github.com/anchore/syft/syft/pkg/cataloger/common"
)

// NewGemFileLockCataloger returns a new Bundler cataloger object tailored for parsing index-oriented files (e.g. Gemfile.lock).
func NewGemFileLockCataloger() *common.GenericCataloger {
	globParsers := map[string]common.ParserFn{
		"**/Gemfile.lock": parseGemFileLockEntries,
	}

	return common.NewGenericCataloger(nil, globParsers, "ruby-gemfile-cataloger")
}

// NewGemSpecCataloger returns a new Bundler cataloger object tailored for detecting installations of gems (e.g. Gemspec).
func NewGemSpecCataloger() *common.GenericCataloger {
	globParsers := map[string]common.ParserFn{
		"**/specifications/**/*.gemspec": parseGemSpecEntries,
	}

	return common.NewGenericCataloger(nil, globParsers, "ruby-gemspec-cataloger")
}
