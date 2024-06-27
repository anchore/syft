package options

import "github.com/anchore/clio"

type javaScriptConfig struct {
	SearchRemoteLicenses bool   `json:"search-remote-licenses" yaml:"search-remote-licenses" mapstructure:"search-remote-licenses"`
	NpmBaseURL           string `json:"npm-base-url" yaml:"npm-base-url" mapstructure:"npm-base-url"`
}

var _ interface {
	clio.FieldDescriber
} = (*javaScriptConfig)(nil)

func (o *javaScriptConfig) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.SearchRemoteLicenses, `enables Syft to use the network to fill in more detailed license information`)
	descriptions.Add(&o.NpmBaseURL, `base NPM url to use`)
}
