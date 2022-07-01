package pkg

import (
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/linux"
)

type ConanMetadata struct {
	Name    string `mapstructure:"name" json:"name"`
	Version string `mapstructure:"version" json:"version"`
}

func (m ConanMetadata) PackageURL(_ *linux.Release) string {
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
