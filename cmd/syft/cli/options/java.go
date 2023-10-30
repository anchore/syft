package options

type java struct {
	SearchMavenForLicenses bool   `yaml:"search-maven-for-licenses" json:"search-maven-for-licenses" mapstructure:"search-maven-for-licenses"`
	MavenURL               string `yaml:"maven-url" json:"maven-url" mapstructure:"maven-url"`
}
