package pkg

import (
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/linux"
)

var _ urlIdentifier = (*HackageMetadata)(nil)

type HackageMetadata struct {
	Name        string  `mapstructure:"name" json:"name"`
	Version     string  `mapstructure:"version" json:"version"`
	PkgHash     *string `mapstructure:"pkgHash" json:"pkgHash,omitempty"`
	SnapshotURL *string `mapstructure:"snapshotURL" json:"snapshotURL,omitempty"`
}

func (m HackageMetadata) PackageURL(_ *linux.Release) string {
	var qualifiers packageurl.Qualifiers

	return packageurl.NewPackageURL(
		packageurl.TypeHackage,
		"",
		m.Name,
		m.Version,
		qualifiers,
		"",
	).ToString()
}
