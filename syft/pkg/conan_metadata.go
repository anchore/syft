package pkg

import (
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/linux"
)

type ConanMetadata struct {
	Name    string `mapstructure:"name" json:"name"`
	Version string `mapstructure:"version" json:"version"`
	Options string `mapstructure:"options" json:"options"`
	Path    string `mapstructure:"path" json:"path"`
	Context string `mapstructure:"context" json:"context"`
}

func (m ConanMetadata) PackageURL(_ *linux.Release) string {
	var qualifiers packageurl.Qualifiers

	return packageurl.NewPackageURL(
		packageurl.TypeConan,
		"",
		m.Name,
		m.Version,
		qualifiers,
		"",
	).ToString()
}
