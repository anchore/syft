package pkg

import (
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/linux"
)

type DotnetDepsMetadata struct {
	Name     string `mapstructure:"name" json:"name"`
	Version  string `mapstructure:"version" json:"version"`
	Path     string `mapstructure:"path" json:"path"`
	Sha512   string `mapstructure:"sha512" json:"sha512"`
	HashPath string `mapstructure:"hashPath" json:"hashPath"`
}

func (m DotnetDepsMetadata) PackageURL(_ *linux.Release) string {
	var qualifiers packageurl.Qualifiers

	return packageurl.NewPackageURL(
		packageurl.TypeDotnet,
		"",
		m.Name,
		m.Version,
		qualifiers,
		"",
	).ToString()
}
