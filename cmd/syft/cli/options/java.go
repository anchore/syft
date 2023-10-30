package options

type java struct {
	SearchMavenForLicenses bool   `yaml:"search-maven-for-licenses" json:"search-maven-for-licenses" mapstructure:"search-maven-for-licenses"`
	MavenCentralURL        string `yaml:"maven-central-url" json:"maven-central-url" mapstructure:"maven-central-url"`
}
