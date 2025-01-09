package options

import (
	"time"

	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/pkg/cataloger/rust"
)

type rustConfig struct {
	InsecureSkipTLSVerify *bool         `yaml:"insecure-skip-tls-verify" json:"insecure-skip-tls-verify" mapstructure:"insecure-skip-tls-verify"`
	UseCratesEnrichment   *bool         `json:"use-crates-enrichment" yaml:"use-crates-enrichment" mapstructure:"use-crates-enrichment"`
	Proxy                 string        `yaml:"proxy,omitempty" json:"proxy,omitempty" mapstructure:"proxy"`
	CratesBaseURL         string        `yaml:"crates-base-url" json:"crates-base-url" mapstructure:"crates-base-url"`
	CratesTimeout         time.Duration `yaml:"crates-timeout" json:"crates-timeout" mapstructure:"crates-timeout"`
}

var _ interface {
	clio.FieldDescriber
} = (*rustConfig)(nil)

func defaultRustConfig() rustConfig {
	def := rust.DefaultCatalogerConfig()
	return rustConfig{
		InsecureSkipTLSVerify: &def.InsecureSkipTLSVerify,
		UseCratesEnrichment:   &def.UseCratesEnrichment,
		Proxy:                 def.Proxy,
		CratesBaseURL:         def.CratesBaseURL,
		CratesTimeout:         def.CratesTimeout,
	}
}

func (o *rustConfig) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.UseCratesEnrichment, `enables Syft to use the network to fill in more detailed package information using crates.io`)
	descriptions.Add(&o.InsecureSkipTLSVerify, `skip TLS certificate verification`)
	descriptions.Add(&o.CratesBaseURL, `base URL to use if not using crates.io`)
	descriptions.Add(&o.CratesTimeout, `timeout for requests to crates.io`)
	descriptions.Add(&o.Proxy, `proxy to use when connecting to remote services`)
}
