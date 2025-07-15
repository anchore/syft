package options

import (
	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/pkg/cataloger/nix"
)

type nixConfig struct {
	CaptureOwnedFiles bool `json:"capture-owned-files" yaml:"capture-owned-files" mapstructure:"capture-owned-files"`
}

func defaultNixConfig() nixConfig {
	def := nix.DefaultConfig()
	return nixConfig{
		def.CaptureOwnedFiles,
	}
}

var _ interface {
	clio.FieldDescriber
} = (*nixConfig)(nil)

func (o *nixConfig) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.CaptureOwnedFiles, `enumerate all files owned by packages found within Nix store paths`)
}
