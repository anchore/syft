package options

import (
	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/pkg/cataloger/rust"
)

type rustConfig struct {
	IncludeDevDependencies bool `json:"include-dev-dependencies" yaml:"include-dev-dependencies" mapstructure:"include-dev-dependencies"`
}

func defaultRustConfig() rustConfig {
	return rustConfig{IncludeDevDependencies: rust.DefaultCatalogerConfig().IncludeDevDependencies}
}

func (o *rustConfig) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.IncludeDevDependencies, `include dependencies used only for tests, examples, and benchmarks; requires Cargo.toml files to exclude them`)
}
