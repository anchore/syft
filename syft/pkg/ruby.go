package pkg

import (
	"github.com/anchore/syft/syft/sort"
)

// RubyGemspec represents all metadata parsed from the *.gemspec file
type RubyGemspec struct {
	Name    string `mapstructure:"name" json:"name"`
	Version string `mapstructure:"version" json:"version"`
	// note regarding if Files can contribute to GemMetadata being able to implement FileOwner: this list is a
	// "logical" list of files, not a list of paths that can be used to find the files without additional processing.
	//
	// For example: The "bundler" gem has a file entry of:
	//   "lib/bundler/vendor/uri/lib/uri/ldap.rb"
	// but the actual file is located at:
	//   "/usr/local/lib/ruby/3.2.0/bundler/vendor/uri/lib/uri/ldap.rb"
	// which do not match (the "lib" prefix is missing even for relative processing).
	//
	// without additional information about:
	// 	- the gem installation path
	// 	- the ruby installation path
	// 	- the ruby version
	// 	- environment variables (e.g. GEM_HOME) that may affect the gem installation path
	// ... we can't reliably determine the full path to the file on disk, thus cannot implement FileOwner (...yet...).
	Files    []string `mapstructure:"files" json:"files,omitempty"`
	Authors  []string `mapstructure:"authors" json:"authors,omitempty"`
	Homepage string   `mapstructure:"homepage" json:"homepage,omitempty"`
}

func (spec RubyGemspec) Compare(other RubyGemspec) int {
	if i := sort.CompareOrd(spec.Name, other.Name); i != 0 {
		return i
	}
	if i := sort.CompareOrd(spec.Version, other.Version); i != 0 {
		return i
	}
	if i := sort.CompareArraysOrd(spec.Files, other.Files); i != 0 {
		return i
	}
	if i := sort.CompareArraysOrd(spec.Authors, other.Authors); i != 0 {
		return i
	}
	if i := sort.CompareOrd(spec.Homepage, other.Homepage); i != 0 {
		return i
	}
	return 0
}

func (spec RubyGemspec) TryCompare(other any) (bool, int) {
	if otherRuby, exists := other.(RubyGemspec); exists {
		return true, spec.Compare(otherRuby)
	}
	return false, 0
}
