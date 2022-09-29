package pkg

import (
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/linux"
)

type ConanMetadata struct {
	Ref string `mapstructure:"ref" json:"ref"`
}

func (m ConanMetadata) PackageURL(_ *linux.Release) string {
	var qualifiers packageurl.Qualifiers

	name, version := m.NameAndVersion()

	return packageurl.NewPackageURL(
		packageurl.TypeConan,
		"",
		name,
		version,
		qualifiers,
		"",
	).ToString()
}

// NameAndVersion tries to return the name and version of a cpp package
// given the ref format: pkg/version
// it returns empty strings if ref is empty or parsing is unsuccessful
func (m ConanMetadata) NameAndVersion() (name, version string) {
	if len(m.Ref) < 1 {
		return name, version
	}

	splits := strings.Split(strings.TrimSpace(m.Ref), "/")

	if len(splits) < 2 {
		return name, version
	}

	return splits[0], splits[1]
}
