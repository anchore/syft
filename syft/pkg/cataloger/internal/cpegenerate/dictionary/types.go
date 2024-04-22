package dictionary

const (
	EcosystemNPM            = "npm"
	EcosystemRubyGems       = "rubygems"
	EcosystemPyPI           = "pypi"
	EcosystemPHPPear        = "php_pear"
	EcosystemPHPPecl        = "php_pecl"
	EcosystemJenkinsPlugins = "jenkins_plugins"
	EcosystemRustCrates     = "rust_crates"
)

type Indexed struct {
	EcosystemPackages map[string]Packages `json:"ecosystems"`
}

type Packages map[string]string
