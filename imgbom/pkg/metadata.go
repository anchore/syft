package pkg

// TODO: consider keeping the remaining values as an embedded map
// Available fields are described at http://manpages.ubuntu.com/manpages/xenial/man1/dpkg-query.1.html
// in the --showformat section
type DpkgMetadata struct {
	Package string `mapstructure:"Package"`
	Source  string `mapstructure:"Source"`
	Version string `mapstructure:"Version"`
}
