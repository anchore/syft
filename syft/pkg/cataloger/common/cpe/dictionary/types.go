package dictionary

const (
	EcosystemNPM            = "npm"
	EcosystemRubyGems       = "rubygems"
	EcosystemPyPI           = "pypi"
	EcosystemJenkinsPlugins = "jenkins_plugins"
	EcosystemRustCrates     = "rust_crates"
)

type Indexed struct {
	EcosystemPackages map[string]Packages `json:"ecosystems"`
}

type Packages map[string]string
