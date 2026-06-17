package options

import (
	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/pkg/cataloger/julia"
)

type juliaConfig struct {
	IncludeExtras   bool `json:"include-extras" yaml:"include-extras" mapstructure:"include-extras"`
	IncludeWeakDeps bool `json:"include-weakdeps" yaml:"include-weakdeps" mapstructure:"include-weakdeps"`
}

func defaultJuliaConfig() juliaConfig {
	def := julia.DefaultCatalogerConfig()
	return juliaConfig{
		IncludeExtras:   def.IncludeExtras,
		IncludeWeakDeps: def.IncludeWeakDeps,
	}
}

var _ interface {
	clio.FieldDescriber
} = (*juliaConfig)(nil)

func (o *juliaConfig) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.IncludeExtras, `include extra dependencies (such as test dependencies) in the catalog results even if they are not installed`)
	descriptions.Add(&o.IncludeWeakDeps, `include weak dependencies (dependency extensions) in the catalog results even if they are not installed`)
}
