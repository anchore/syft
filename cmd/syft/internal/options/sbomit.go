package options

import (
	"github.com/anchore/clio"
)

type sbomitConfig struct {
	Enable      bool   `json:"enable" yaml:"enable" mapstructure:"enable"`
	Attestation string `json:"attestation" yaml:"attestation" mapstructure:"attestation"`
}

var _ interface {
	clio.FieldDescriber
} = (*sbomitConfig)(nil)

func (o *sbomitConfig) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.Enable, `enrich the SBOM using in-toto/witness attestations`)
	descriptions.Add(&o.Attestation, `path to a specific attestation to use (searches the scan target if empty)`)
}

func defaultSBOMit() sbomitConfig {
	return sbomitConfig{}
}
