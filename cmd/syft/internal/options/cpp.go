package options

import (
	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/pkg/cataloger/cpp"
)

type cppConfig struct {
	VcpkgAllowGitClone *bool `yaml:"vcpkg-allow-git-clone" json:"vcpkg-allow-git-clone" mapstructure:"vcpkg-allow-git-clone"`
}

func defaultCppConfig() cppConfig {
	// reference the cataloger default so capability generation can associate this config with the cpp
	// ecosystem (it discovers ecosystem configs by their cataloger import). the value itself stays nil:
	// nil defaults to false (no network), and leaving it unset lets --enrich opt in. cloning requires a
	// network connection, which must be opt-in.
	_ = cpp.DefaultCatalogerConfig()
	return cppConfig{
		VcpkgAllowGitClone: nil,
	}
}

var _ interface {
	clio.FieldDescriber
} = (*cppConfig)(nil)

func (o *cppConfig) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.VcpkgAllowGitClone, `enables Syft to use clone remote repositories for vcpkg custom git registries. 
	(also useful if the builtin vcpkg registry is not cloned locally)`)
}
