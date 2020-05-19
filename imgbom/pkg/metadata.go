package pkg

// TODO: consider keeping the remaining values as an embedded map
// Available fields are described at http://manpages.ubuntu.com/manpages/xenial/man1/dpkg-query.1.html
// in the --showformat section
type DpkgMetadata struct {
	Package        string `mapstructure:"Package"`
	Architecture   string `mapstructure:"Architecture"`
	DependsPkgs    string `mapstructure:"Depends"`
	InstalledSize  string `mapstructure:"Installed-Size"`
	Maintainer     string `mapstructure:"Maintainer"`
	Priority       string `mapstructure:"Priority"`
	ProvidesPkgs   string `mapstructure:"Provides"`
	RecommendsPkgs string `mapstructure:"Recommends"`
	ReplacesPkgs   string `mapstructure:"Replaces"`
	Status         string `mapstructure:"Status"`
	SuggestsPkgs   string `mapstructure:"Suggests"`
	Version        string `mapstructure:"Version"`
	ConfigFiles    string `mapstructure:"Conffiles"`
}
