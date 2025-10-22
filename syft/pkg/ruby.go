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
