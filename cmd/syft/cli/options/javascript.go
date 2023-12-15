package options

type javascriptConfig struct {
	SearchRemoteLicenses bool   `json:"search-remote-licenses" yaml:"search-remote-licenses" mapstructure:"search-remote-licenses"`
	NpmBaseURL           string `json:"npm-base-url" yaml:"npm-base-url" mapstructure:"npm-base-url"`
}
