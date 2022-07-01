package pkg

import (
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/linux"
)

var _ urlIdentifier = (*CocoapodsMetadata)(nil)

type CocoapodsMetadata struct {
	Name    string `mapstructure:"name" json:"name"`
	Version string `mapstructure:"version" json:"version"`
	PkgHash string `mapstructure:"pkgHash" json:"pkgHash"`
}

func (m CocoapodsMetadata) PackageURL(_ *linux.Release) string {
	var qualifiers packageurl.Qualifiers

	return packageurl.NewPackageURL(
		packageurl.TypeCocoapods,
		"",
		m.Name,
		m.Version,
		qualifiers,
		"",
	).ToString()
}
