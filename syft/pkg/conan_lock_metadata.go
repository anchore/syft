package pkg

import (
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/linux"
)

type ConanLockMetadata struct {
	Ref     string            `json:"ref"`
	Options map[string]string `json:"options"`
	Path    string            `json:"path"`
	Context string            `json:"context"`
}

func (m ConanLockMetadata) PackageURL(_ *linux.Release) string {
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

func (m ConanLockMetadata) NameAndVersion() (name, version string) {
	if len(m.Ref) < 1 {
		return name, version
	}

	splits := strings.Split(strings.Split(m.Ref, "@")[0], "/")
	if len(splits) < 2 {
		return name, version
	}

	return splits[0], splits[1]
}
