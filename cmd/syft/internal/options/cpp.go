package options

import (
	"github.com/anchore/clio"
)

type cppConfig struct {
	VcpkgAllowGitClone                 *bool  `yaml:"vcpkg-allow-git-clone" json:"vcpkg-allow-git-clone" mapstructure:"vcpkg-allow-git-clone"`
}

func defaultCppConfig() cppConfig {
	return cppConfig{
		VcpkgAllowGitClone: nil, // this defaults to false, which is the API default
	}
}

var _ interface {
	clio.FieldDescriber
} = (*cppConfig)(nil)

func (o *cppConfig) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.VcpkgAllowGitClone, `enables Syft to use clone remote repositories for vcpkg custom git registries. 
	(also useful if the builtin vcpkg registry is not cloned locally)`)
}
