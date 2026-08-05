package pkg

// RubyGemspec represents all metadata parsed from the *.gemspec file
type RubyGemspec struct {
	// Name is gem name as specified in the gemspec
	Name string `mapstructure:"name" json:"name"`

	// Version is gem version as specified in the gemspec
	Version string `mapstructure:"version" json:"version"`

	// Files is logical list of files in the gem (NOT directly usable as filesystem paths. Example: bundler gem lists "lib/bundler/vendor/uri/lib/uri/ldap.rb" but actual path is "/usr/local/lib/ruby/3.2.0/bundler/vendor/uri/lib/uri/ldap.rb". Would need gem installation path, ruby version, and env vars like GEM_HOME to resolve actual paths.)
	Files []string `mapstructure:"files" json:"files,omitempty"`

	// Authors are the list of gem authors (stored as array regardless of using `author` or `authors` method in gemspec)
	Authors []string `mapstructure:"authors" json:"authors,omitempty"`

	// Homepage is project homepage URL
	Homepage string `mapstructure:"homepage" json:"homepage,omitempty"`
}

// RubyGemfileLockEntry represents a single gem entry parsed from a Gemfile.lock file.
type RubyGemfileLockEntry struct {
	// Name is the gem name as locked in the Gemfile.lock
	Name string `mapstructure:"name" json:"name"`

	// Version is the resolved gem version as locked in the Gemfile.lock
	Version string `mapstructure:"version" json:"version"`

	// Dependencies are the names of the gems this entry depends on, as declared
	// in the entry's indented dependency list. Used to derive dependency-of
	// relationships between the locked gems.
	Dependencies []string `mapstructure:"dependencies" json:"dependencies,omitempty"`
}
