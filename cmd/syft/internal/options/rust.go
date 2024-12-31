package options

import (
	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/pkg/cataloger/rust"
)

type rustConfig rust.CatalogerConfig

var _ interface {
	clio.FieldDescriber
} = (*rustConfig)(nil)

func defaultRustConfig() rustConfig {
	return rustConfig(rust.DefaultCatalogerConfig())
}

func (o *rustConfig) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.UseCratesEnrichment, `enables Syft to use the network to fill in more detailed package information using crates.io`)
	descriptions.Add(&o.InsecureSkipTLSVerify, `skip TLS certificate verification`)
	descriptions.Add(&o.CratesBaseURL, `base URL to use if not using crates.io`)
	descriptions.Add(&o.CratesTimeout, `timeout for requests to crates.io`)
	descriptions.Add(&o.Proxy, `proxy to use when connecting to remote services`)
}
