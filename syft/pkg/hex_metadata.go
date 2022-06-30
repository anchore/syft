package pkg

import (
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/linux"
)

var _ urlIdentifier = (*HexMetadata)(nil)

type HexMetadata struct {
	Name       string `mapstructure:"name" json:"name"`
	Version    string `mapstructure:"version" json:"version"`
	PkgHash    string `mapstructure:"pkgHash" json:"pkgHash"`
	PkgHashExt string `mapstructure:"pkgHashExt" json:"pkgHashExt"`
}

func (m HexMetadata) PackageURL(_ *linux.Release) string {
	var qualifiers packageurl.Qualifiers

	return packageurl.NewPackageURL(
		packageurl.TypeHex,
		"",
		m.Name,
		m.Version,
		qualifiers,
		"",
	).ToString()
}
