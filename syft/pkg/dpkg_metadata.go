package pkg

import (
	"github.com/anchore/syft/syft/distro"
	"github.com/package-url/packageurl-go"
)

// DpkgMetadata represents all captured data for a Debian package DB entry; available fields are described
// at http://manpages.ubuntu.com/manpages/xenial/man1/dpkg-query.1.html in the --showformat section.
type DpkgMetadata struct {
	Package      string `mapstructure:"Package" json:"package"`
	Source       string `mapstructure:"Source" json:"source"`
	Version      string `mapstructure:"Version" json:"version"`
	Architecture string `mapstructure:"Architecture" json:"architecture"`
	// TODO: consider keeping the remaining values as an embedded map
}

func (m DpkgMetadata) PackageURL(d distro.Distro) string {
	pURL := packageurl.NewPackageURL(
		// TODO: replace with `packageurl.TypeDebian` upon merge of https://github.com/package-url/packageurl-go/pull/21
		"deb",
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
