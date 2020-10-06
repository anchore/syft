/*
Package bundler provides a concrete Cataloger implementation for Ruby Gemfile.lock bundler files.
*/
package bundler

import (
	"github.com/anchore/syft/syft/cataloger/common"
)

// NewGemfileLockCataloger returns a new Bundler cataloger object tailored for parsing index-oriented files (e.g. Gemfile.lock).
func NewGemfileLockCataloger() *common.GenericCataloger {
	globParsers := map[string]common.ParserFn{
		"**/Gemfile.lock": parseGemfileLockEntries,
	}

	return common.NewGenericCataloger(nil, globParsers, "ruby-gemfile-cataloger")
}

// NewGemspecCataloger returns a new Bundler cataloger object tailored for detecting installations of gems (e.g. Gemspec).
func NewGemspecCataloger() *common.GenericCataloger {
	globParsers := map[string]common.ParserFn{
		"**/specification/*.gemspec": parseGemspecEntries,
	}

	return common.NewGenericCataloger(nil, globParsers, "ruby-gemspec-cataloger")
}
