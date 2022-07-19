package pkg

import (
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/distro"
)

const NixStoreGlob = "/nix/store/**"

type NixStoreMetadata struct {
	Package       string           `mapstructure:"Package" json:"package"`
	Architecture  string           `mapstructure:"A" json:"architecture"`
	Source        string           `mapstructure:"Source" json:"source"`
	Version       string           `mapstructure:"Version" json:"version"`
	SourceVersion string           `mapstructure:"SourceVersion" json:"sourceVersion"`
}

func (m NixStoreMetadata) PackageURL(d *distro.Distro) string {
	if d == nil {
		return ""
	}
	pURL := packageurl.NewPackageURL(
		// TODO: replace with `packageurl.TypeDebian` upon merge of https://github.com/package-url/packageurl-go/pull/21
		// TODO: or, since we're now using an Anchore fork of this module, we could do this sooner.
		"nix",
		d.Type.String(),
		m.Package,
		m.Version,
		packageurl.Qualifiers{
			{
				Key:   "arch",
				Value: m.Architecture,
			},
		},
		"")
	return pURL.ToString()
}
